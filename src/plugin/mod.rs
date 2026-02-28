//! Plugin system for Vow
//! 
//! This module provides a plugin architecture that allows external rule plugins
//! to extend Vow's detection capabilities. It supports:
//! 
//! - WASM-based plugins for cross-platform compatibility
//! - Plugin discovery from `.vow/plugins/` directory or custom paths
//! - Plugin manifest files (`plugin.toml`) with metadata and configuration
//! - Integration with the existing rules engine
//! 
//! ## Plugin Development
//! 
//! Plugins must implement the `VowPlugin` trait and provide:
//! - `init()`: Initialize the plugin
//! - `rules()`: Return rules this plugin provides
//! - `analyze()`: Analyze content and return issues
//! 
//! See the examples directory for plugin development templates.

pub mod interface;
pub mod loader;

pub use interface::{
    VowPlugin, PluginManifest, PluginType, PluginError, PluginRule, 
    PluginPattern, PluginContext
};
pub use loader::PluginLoader;

use crate::{Issue, rules::engine::RuleEngine};
use std::path::{Path, PathBuf};

/// Plugin manager that integrates plugins with the main Vow engine
pub struct PluginManager {
    loader: PluginLoader,
    plugin_dirs: Vec<PathBuf>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Result<Self, PluginError> {
        Ok(Self {
            loader: PluginLoader::new()?,
            plugin_dirs: Vec::new(),
        })
    }

    /// Add a plugin directory to search for plugins
    pub fn add_plugin_dir<P: AsRef<Path>>(&mut self, plugin_dir: P) {
        self.plugin_dirs.push(plugin_dir.as_ref().to_path_buf());
    }

    /// Load all plugins from configured directories
    pub fn load_plugins(&mut self) -> Result<(), PluginError> {
        for plugin_dir in &self.plugin_dirs.clone() {
            self.loader.load_plugins_from_dir(plugin_dir)?;
        }
        
        // Initialize all loaded plugins
        for plugin in self.loader.get_plugins().values() {
            // Note: This is a simplified approach. In practice, we'd need
            // mutable access to plugins for initialization.
            // For now, plugins are expected to handle initialization lazily.
        }
        
        Ok(())
    }

    /// Get plugin-provided rules and merge them with the rules engine
    pub fn extend_rules_engine(&self, rules_engine: &mut RuleEngine) -> Result<(), PluginError> {
        for plugin in self.loader.get_plugins().values() {
            let plugin_rules = plugin.rules()?;
            
            // Convert plugin rules to rules engine format
            for plugin_rule in plugin_rules {
                // In a full implementation, we would:
                // 1. Convert PluginRule to the format expected by RuleEngine
                // 2. Add the converted rules to the rules engine
                // 3. Handle any conflicts or naming collisions
                
                // For now, this is a placeholder that demonstrates the integration point
                println!("Would add plugin rule: {} from plugin: {}", 
                    plugin_rule.name, 
                    plugin.metadata().name
                );
            }
        }
        
        Ok(())
    }

    /// Apply plugin-based analysis to content
    pub fn analyze_with_plugins(
        &self,
        file_path: &Path,
        content: &str,
    ) -> Result<Vec<Issue>, PluginError> {
        let mut all_issues = Vec::new();
        
        for plugin in self.loader.get_plugins().values() {
            // Check if this plugin supports the file type
            if let Some(ref supported_types) = plugin.metadata().supported_file_types {
                let file_extension = file_path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.to_lowercase());
                    
                if let Some(ext) = file_extension {
                    if !supported_types.contains(&ext) {
                        continue; // Skip this plugin for this file type
                    }
                }
            }
            
            let plugin_issues = plugin.analyze(file_path, content)?;
            all_issues.extend(plugin_issues);
        }
        
        Ok(all_issues)
    }

    /// Get information about loaded plugins
    pub fn get_plugin_info(&self) -> Vec<(&str, &PluginManifest)> {
        self.loader
            .get_plugins()
            .iter()
            .map(|(name, plugin)| (name.as_str(), plugin.metadata()))
            .collect()
    }

    /// Get the number of loaded plugins
    pub fn plugin_count(&self) -> usize {
        self.loader.plugin_count()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default plugin manager")
    }
}

/// Discover plugins from standard locations
pub fn discover_plugin_directories(project_root: &Path) -> Vec<PathBuf> {
    let mut plugin_dirs = Vec::new();
    
    // Check .vow/plugins directory in project root
    let vow_plugins = project_root.join(".vow").join("plugins");
    if vow_plugins.exists() {
        plugin_dirs.push(vow_plugins);
    }
    
    // Check for global plugin directory (future enhancement)
    // let global_plugins = dirs::config_dir()
    //     .map(|config| config.join("vow").join("plugins"));
    // if let Some(global) = global_plugins {
    //     if global.exists() {
    //         plugin_dirs.push(global);
    //     }
    // }
    
    plugin_dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_plugin_manager_creation() {
        let manager = PluginManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_discover_plugin_directories() {
        let temp_dir = TempDir::new().unwrap();
        let vow_dir = temp_dir.path().join(".vow");
        let plugins_dir = vow_dir.join("plugins");
        
        fs::create_dir_all(&plugins_dir).unwrap();
        
        let discovered = discover_plugin_directories(temp_dir.path());
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0], plugins_dir);
    }

    #[test]
    fn test_discover_no_plugin_directories() {
        let temp_dir = TempDir::new().unwrap();
        let discovered = discover_plugin_directories(temp_dir.path());
        assert_eq!(discovered.len(), 0);
    }

    #[test]
    fn test_plugin_manager_add_directory() {
        let mut manager = PluginManager::new().unwrap();
        let test_path = PathBuf::from("/test/path");
        
        manager.add_plugin_dir(&test_path);
        assert_eq!(manager.plugin_dirs.len(), 1);
        assert_eq!(manager.plugin_dirs[0], test_path);
    }
}