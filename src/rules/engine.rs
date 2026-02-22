use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// YAML-based rule engine for configurable verification rules
pub struct RuleEngine {
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub patterns: Vec<Pattern>,
    pub file_types: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pattern {
    pub pattern_type: String, // "regex", "contains", "starts_with", etc.
    pub value: String,
    pub message: String,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }
    
    /// Load rules from a YAML file or directory
    pub fn load_rules(&mut self, rules_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        if rules_path.is_file() {
            self.load_rule_file(rules_path)?;
        } else if rules_path.is_dir() {
            for entry in fs::read_dir(rules_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yaml") 
                    || path.extension().and_then(|s| s.to_str()) == Some("yml") {
                    self.load_rule_file(&path)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Load rules from a single YAML file
    fn load_rule_file(&mut self, file_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;
        let rules: Vec<Rule> = serde_yaml::from_str(&content)?;
        self.rules.extend(rules);
        
        Ok(())
    }
    
    /// Apply loaded rules to content
    pub fn apply_rules(&self, content: &str, file_type: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        
        for rule in &self.rules {
            // Check if rule applies to this file type
            if let Some(ref types) = rule.file_types {
                if !types.contains(&file_type.to_string()) {
                    continue;
                }
            }
            
            // Apply patterns
            for pattern in &rule.patterns {
                if self.pattern_matches(&pattern, content) {
                    matches.push(RuleMatch {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        message: pattern.message.clone(),
                        severity: rule.severity.clone(),
                        line: None, // TODO: implement line detection
                    });
                }
            }
        }
        
        matches
    }
    
    /// Check if a pattern matches the content
    fn pattern_matches(&self, pattern: &Pattern, content: &str) -> bool {
        match pattern.pattern_type.as_str() {
            "contains" => content.contains(&pattern.value),
            "starts_with" => content.starts_with(&pattern.value),
            "ends_with" => content.ends_with(&pattern.value),
            // TODO: implement regex patterns
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub message: String,
    pub severity: String,
    pub line: Option<usize>,
}