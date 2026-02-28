use crate::plugin::interface::{PluginManifest, PluginType, PluginError, VowPlugin};
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use wasmtime::{Engine, Module, Store, Instance, Func, Linker};

/// Plugin loader responsible for discovering and loading plugins
pub struct PluginLoader {
    engine: Engine,
    plugins: HashMap<String, Box<dyn VowPlugin>>,
}

impl PluginLoader {
    pub fn new() -> Result<Self, PluginError> {
        let engine = Engine::default();
        
        Ok(Self {
            engine,
            plugins: HashMap::new(),
        })
    }

    /// Load all plugins from a directory
    pub fn load_plugins_from_dir<P: AsRef<Path>>(&mut self, plugin_dir: P) -> Result<(), PluginError> {
        let plugin_dir = plugin_dir.as_ref();
        
        if !plugin_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(plugin_dir).map_err(|e| {
            PluginError::FileNotFound(format!("Cannot read plugin directory: {}", e))
        })? {
            let entry = entry.map_err(|e| {
                PluginError::FileNotFound(format!("Cannot read directory entry: {}", e))
            })?;
            
            let path = entry.path();
            if path.is_dir() {
                self.load_plugin_from_dir(&path)?;
            }
        }

        Ok(())
    }

    /// Load a single plugin from its directory
    fn load_plugin_from_dir<P: AsRef<Path>>(&mut self, plugin_path: P) -> Result<(), PluginError> {
        let plugin_path = plugin_path.as_ref();
        let manifest_path = plugin_path.join("plugin.toml");
        
        if !manifest_path.exists() {
            return Ok(()); // Skip directories without plugin.toml
        }

        let manifest_content = fs::read_to_string(&manifest_path).map_err(|e| {
            PluginError::ManifestError(format!("Cannot read manifest: {}", e))
        })?;

        let manifest: PluginManifest = toml::from_str(&manifest_content).map_err(|e| {
            PluginError::ManifestError(format!("Invalid manifest format: {}", e))
        })?;

        let entry_point_path = plugin_path.join(&manifest.entry_point);
        if !entry_point_path.exists() {
            return Err(PluginError::FileNotFound(format!(
                "Entry point not found: {}",
                entry_point_path.display()
            )));
        }

        match manifest.plugin_type {
            PluginType::Wasm => {
                let plugin = self.load_wasm_plugin(&entry_point_path, manifest)?;
                self.plugins.insert(plugin.metadata().name.clone(), plugin);
            }
            PluginType::Native => {
                return Err(PluginError::UnsupportedType("Native plugins not yet supported".to_string()));
            }
        }

        Ok(())
    }

    /// Load a WASM-based plugin
    fn load_wasm_plugin<P: AsRef<Path>>(
        &self,
        wasm_path: P,
        manifest: PluginManifest,
    ) -> Result<Box<dyn VowPlugin>, PluginError> {
        let wasm_bytes = fs::read(wasm_path.as_ref()).map_err(|e| {
            PluginError::FileNotFound(format!("Cannot read WASM file: {}", e))
        })?;

        let module = Module::from_binary(&self.engine, &wasm_bytes).map_err(|e| {
            PluginError::WasmError(format!("Cannot compile WASM module: {}", e))
        })?;

        let plugin = WasmPlugin::new(module, manifest)?;
        Ok(Box::new(plugin))
    }

    /// Get all loaded plugins
    pub fn get_plugins(&self) -> &HashMap<String, Box<dyn VowPlugin>> {
        &self.plugins
    }

    /// Get a specific plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&Box<dyn VowPlugin>> {
        self.plugins.get(name)
    }

    /// Get the number of loaded plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new().expect("Failed to create default plugin loader")
    }
}

/// WASM plugin implementation
struct WasmPlugin {
    module: Module,
    manifest: PluginManifest,
    initialized: bool,
}

impl WasmPlugin {
    fn new(module: Module, manifest: PluginManifest) -> Result<Self, PluginError> {
        Ok(Self {
            module,
            manifest,
            initialized: false,
        })
    }
    
    /// Execute a WASM function with the given name and parameters
    fn execute_wasm_function(
        &self,
        function_name: &str,
        params: &str,
    ) -> Result<String, PluginError> {
        let mut store = Store::new(self.module.engine(), ());
        
        let mut linker = Linker::new(self.module.engine());
        
        // Add host functions that plugins can call
        linker
            .func_wrap("host", "log", |param: i32| {
                println!("Plugin log: {}", param);
            })
            .map_err(|e| PluginError::WasmError(format!("Cannot link host functions: {}", e)))?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| PluginError::WasmError(format!("Cannot instantiate module: {}", e)))?;

        // For now, return a placeholder result
        // In a full implementation, we would:
        // 1. Call the WASM function with the parameters
        // 2. Handle memory allocation/deallocation 
        // 3. Convert between Rust and WASM types
        // 4. Return the actual result from the WASM function
        Ok(format!("{{\"result\": \"placeholder for {}\"}}", function_name))
    }
}

impl VowPlugin for WasmPlugin {
    fn init(&mut self) -> Result<(), PluginError> {
        if self.initialized {
            return Ok(());
        }

        // Initialize the WASM plugin by calling its init function
        let _result = self.execute_wasm_function("init", "{}")?;
        
        self.initialized = true;
        Ok(())
    }

    fn rules(&self) -> Result<Vec<crate::plugin::interface::PluginRule>, PluginError> {
        let result = self.execute_wasm_function("rules", "{}")?;
        
        // Parse the JSON result from the WASM function
        // For now, return empty rules - in a full implementation this would
        // deserialize the actual rules from the WASM function response
        Ok(vec![])
    }

    fn analyze(&self, file_path: &Path, content: &str) -> Result<Vec<crate::Issue>, PluginError> {
        let params = format!(
            r#"{{"file_path": "{}", "content": "{}"}}"#,
            file_path.display(),
            content.replace('"', r#"\""#)
        );
        
        let result = self.execute_wasm_function("analyze", &params)?;
        
        // Parse the JSON result from the WASM function
        // For now, return empty issues - in a full implementation this would
        // deserialize the actual issues from the WASM function response
        Ok(vec![])
    }

    fn metadata(&self) -> &PluginManifest {
        &self.manifest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_plugin_loader_creation() {
        let loader = PluginLoader::new();
        assert!(loader.is_ok());
    }

    #[test]
    fn test_load_plugins_from_nonexistent_dir() {
        let mut loader = PluginLoader::new().unwrap();
        let result = loader.load_plugins_from_dir("/nonexistent/directory");
        assert!(result.is_ok());
        assert_eq!(loader.plugin_count(), 0);
    }

    #[test] 
    fn test_load_plugins_from_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let mut loader = PluginLoader::new().unwrap();
        
        let result = loader.load_plugins_from_dir(temp_dir.path());
        assert!(result.is_ok());
        assert_eq!(loader.plugin_count(), 0);
    }

    #[test]
    fn test_manifest_parsing() {
        let manifest_toml = r#"
name = "test-plugin"
version = "1.0.0"
description = "A test plugin"
author = "Test Author"
entry_point = "plugin.wasm"
plugin_type = "wasm"
supported_file_types = ["rs", "py"]
"#;
        
        let manifest: Result<PluginManifest, _> = toml::from_str(manifest_toml);
        assert!(manifest.is_ok());
        
        let manifest = manifest.unwrap();
        assert_eq!(manifest.name, "test-plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.entry_point, "plugin.wasm");
    }
}