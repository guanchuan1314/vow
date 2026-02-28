//! Simple Rule Plugin Example for Vow
//!
//! This plugin demonstrates basic rule creation and analysis.
//! It provides simple pattern-based rules for detecting common issues.

use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;

// Plugin interface types (normally these would be imported from vow-plugin-sdk)
#[derive(Debug, Deserialize, Serialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub entry_point: String,
    pub plugin_type: String,
    pub supported_file_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub patterns: Vec<PluginPattern>,
    pub file_types: Option<Vec<String>>,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPattern {
    #[serde(rename = "type")]
    pub pattern_type: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: String,
    pub message: String,
    pub line: Option<usize>,
    pub rule: Option<String>,
    pub suggestion: Option<String>,
}

// Plugin implementation
pub struct SimpleRulePlugin {
    manifest: PluginManifest,
    rules: Vec<PluginRule>,
    compiled_patterns: HashMap<String, Vec<Regex>>,
}

impl SimpleRulePlugin {
    pub fn new() -> Self {
        let manifest = PluginManifest {
            name: "simple-rule-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A simple example plugin".to_string()),
            author: Some("Vow Team".to_string()),
            entry_point: "plugin.wasm".to_string(),
            plugin_type: "wasm".to_string(),
            supported_file_types: Some(vec!["rs".to_string(), "py".to_string(), "js".to_string(), "ts".to_string()]),
        };

        let rules = vec![
            PluginRule {
                name: "hardcoded-secret".to_string(),
                description: "Potential hardcoded secret detected".to_string(),
                severity: "medium".to_string(),
                patterns: vec![
                    PluginPattern {
                        pattern_type: "regex".to_string(),
                        pattern: r#"(?i)(api_?key|password|secret|token)\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']"#.to_string(),
                    }
                ],
                file_types: None,
                fix_suggestion: Some("Consider using environment variables or a secure configuration file".to_string()),
            },
            PluginRule {
                name: "todo-comment".to_string(),
                description: "TODO comment found".to_string(),
                severity: "low".to_string(),
                patterns: vec![
                    PluginPattern {
                        pattern_type: "regex".to_string(),
                        pattern: r#"(?i)//\s*todo|#\s*todo|/\*\s*todo"#.to_string(),
                    }
                ],
                file_types: None,
                fix_suggestion: Some("Complete the implementation or create a proper issue to track this work".to_string()),
            },
            PluginRule {
                name: "debug-logging".to_string(),
                description: "Debug logging statement detected".to_string(),
                severity: "low".to_string(),
                patterns: vec![
                    PluginPattern {
                        pattern_type: "regex".to_string(),
                        pattern: r#"(?i)(console\.log|println!|print\(|dbg!)\s*\("#.to_string(),
                    }
                ],
                file_types: None,
                fix_suggestion: Some("Remove debug statements or use proper logging with appropriate levels".to_string()),
            },
        ];

        Self {
            manifest,
            rules,
            compiled_patterns: HashMap::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), String> {
        // Compile regex patterns for efficient matching
        for rule in &self.rules {
            let mut compiled_rule_patterns = Vec::new();
            for pattern in &rule.patterns {
                if pattern.pattern_type == "regex" {
                    match Regex::new(&pattern.pattern) {
                        Ok(regex) => compiled_rule_patterns.push(regex),
                        Err(e) => return Err(format!("Failed to compile regex '{}': {}", pattern.pattern, e)),
                    }
                }
            }
            self.compiled_patterns.insert(rule.name.clone(), compiled_rule_patterns);
        }
        Ok(())
    }

    pub fn rules(&self) -> Result<Vec<PluginRule>, String> {
        Ok(self.rules.clone())
    }

    pub fn analyze(&self, file_path: &str, content: &str) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // Check file type filtering
        let file_extension = std::path::Path::new(file_path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase());

        for rule in &self.rules {
            // Apply file type filtering if specified
            if let Some(ref rule_file_types) = rule.file_types {
                if let Some(ref ext) = file_extension {
                    if !rule_file_types.contains(ext) {
                        continue;
                    }
                }
            }

            // Get compiled patterns for this rule
            if let Some(patterns) = self.compiled_patterns.get(&rule.name) {
                for regex in patterns {
                    for (line_num, line) in content.lines().enumerate() {
                        if regex.is_match(line) {
                            issues.push(Issue {
                                severity: rule.severity.clone(),
                                message: format!("{} ({})", rule.description, self.manifest.name),
                                line: Some(line_num + 1),
                                rule: Some(rule.name.clone()),
                                suggestion: rule.fix_suggestion.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(issues)
    }

    pub fn metadata(&self) -> &PluginManifest {
        &self.manifest
    }
}

// WASM exports (these would be called by the Vow plugin system)
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

static mut PLUGIN: Option<SimpleRulePlugin> = None;

#[no_mangle]
pub extern "C" fn init() -> i32 {
    let mut plugin = SimpleRulePlugin::new();
    match plugin.init() {
        Ok(()) => {
            unsafe {
                PLUGIN = Some(plugin);
            }
            0 // Success
        }
        Err(_) => 1, // Error
    }
}

#[no_mangle]
pub extern "C" fn get_rules() -> *mut c_char {
    unsafe {
        if let Some(ref plugin) = PLUGIN {
            match plugin.rules() {
                Ok(rules) => {
                    if let Ok(json) = serde_json::to_string(&rules) {
                        if let Ok(cstring) = CString::new(json) {
                            return cstring.into_raw();
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn analyze(file_path: *const c_char, content: *const c_char) -> *mut c_char {
    unsafe {
        if let Some(ref plugin) = PLUGIN {
            if let (Ok(path_str), Ok(content_str)) = (
                CStr::from_ptr(file_path).to_str(),
                CStr::from_ptr(content).to_str()
            ) {
                match plugin.analyze(path_str, content_str) {
                    Ok(issues) => {
                        if let Ok(json) = serde_json::to_string(&issues) {
                            if let Ok(cstring) = CString::new(json) {
                                return cstring.into_raw();
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            let _ = CString::from_raw(s);
        }
    }
}

// For testing purposes (this would normally be provided by the plugin SDK)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SimpleRulePlugin::new();
        assert_eq!(plugin.metadata().name, "simple-rule-plugin");
        assert_eq!(plugin.rules().unwrap().len(), 3);
    }

    #[test]
    fn test_hardcoded_secret_detection() {
        let mut plugin = SimpleRulePlugin::new();
        plugin.init().unwrap();

        let content = r#"
let api_key = "sk-1234567890abcdefghijklmnop";
let password = "secretpassword123456789";
"#;

        let issues = plugin.analyze("test.rs", content).unwrap();
        assert!(issues.len() >= 2);
        assert!(issues.iter().any(|i| i.rule.as_ref().unwrap() == "hardcoded-secret"));
    }

    #[test]
    fn test_todo_detection() {
        let mut plugin = SimpleRulePlugin::new();
        plugin.init().unwrap();

        let content = r#"
// TODO: implement this feature
fn incomplete_function() {
    // Todo: add error handling
}
"#;

        let issues = plugin.analyze("test.rs", content).unwrap();
        assert!(issues.len() >= 2);
        assert!(issues.iter().any(|i| i.rule.as_ref().unwrap() == "todo-comment"));
    }

    #[test]
    fn test_debug_logging_detection() {
        let mut plugin = SimpleRulePlugin::new();
        plugin.init().unwrap();

        let content = r#"
console.log("debug info");
println!("Debug: {}", value);
print("something");
dbg!(variable);
"#;

        let issues = plugin.analyze("test.js", content).unwrap();
        assert!(issues.len() >= 4);
        assert!(issues.iter().any(|i| i.rule.as_ref().unwrap() == "debug-logging"));
    }
}