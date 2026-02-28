use crate::{Issue, AnalysisResult};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Plugin manifest structure for plugin.toml files
#[derive(Debug, Deserialize, Serialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub entry_point: String,
    pub plugin_type: PluginType,
    pub supported_file_types: Option<Vec<String>>,
}

/// Types of plugins supported by Vow
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PluginType {
    /// WASM-based plugins for cross-platform rule execution
    Wasm,
    /// Future: native shared library plugins 
    Native,
}

/// Core plugin trait that all plugins must implement
/// This trait defines the interface for plugin lifecycle and capabilities
pub trait VowPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> String {
        self.metadata().name.clone()
    }

    /// Initialize the plugin with any required setup
    /// Called once when the plugin is loaded
    fn init(&mut self) -> Result<(), PluginError>;

    /// Return the rules this plugin provides
    /// These rules will be merged with built-in rules
    fn rules(&self) -> Result<Vec<PluginRule>, PluginError>;

    /// Analyze content using this plugin's logic
    /// Returns analysis results that will be merged with other analyzers
    fn analyze(&self, file_path: &Path, content: &str) -> Result<Vec<Issue>, PluginError>;

    /// Get plugin metadata
    fn metadata(&self) -> &PluginManifest;
}

/// Rule definition provided by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub patterns: Vec<PluginPattern>,
    pub file_types: Option<Vec<String>>,
    pub fix_suggestion: Option<String>,
}

/// Pattern definition for plugin rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPattern {
    #[serde(rename = "type")]
    pub pattern_type: String,
    pub pattern: String,
}

/// Plugin-specific error types
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Plugin execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Plugin manifest error: {0}")]
    ManifestError(String),
    
    #[error("Plugin file not found: {0}")]
    FileNotFound(String),
    
    #[error("Plugin type not supported: {0}")]
    UnsupportedType(String),
    
    #[error("WASM runtime error: {0}")]
    WasmError(String),
}

/// Context passed to plugins during analysis
#[derive(Debug, Clone)]
pub struct PluginContext {
    pub file_path: std::path::PathBuf,
    pub file_type: String,
    pub project_root: std::path::PathBuf,
}

impl PluginContext {
    pub fn new<P: AsRef<Path>>(file_path: P, project_root: P) -> Self {
        let file_path = file_path.as_ref().to_path_buf();
        let file_type = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());
            
        Self {
            file_path,
            file_type,
            project_root: project_root.as_ref().to_path_buf(),
        }
    }
}