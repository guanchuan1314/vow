use std::path::Path;
use std::fs;
use crate::{Issue, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub patterns: Vec<Pattern>,
    pub file_types: Option<Vec<String>>,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Pattern {
    #[serde(rename = "type")]
    pub pattern_type: String,
    pub pattern: String,
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    name: String,
    description: String,
    severity: Severity,
    patterns: Vec<CompiledPattern>,
    file_types: Option<Vec<String>>,
    fix_suggestion: Option<String>,
}

enum CompiledPattern {
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        RuleEngine { rules: Vec::new() }
    }
    
    /// Load rules from a directory
    pub fn load_rules_from_dir(&mut self, rules_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !rules_dir.exists() {
            return Ok(());
        }
        
        for entry in fs::read_dir(rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().is_some_and(|ext| ext == "yaml" || ext == "yml") {
                self.load_rules_from_file(&path)?;
            }
        }
        
        Ok(())
    }
    
    /// Load rules from a single YAML file
    fn load_rules_from_file(&mut self, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;
        let rule: Rule = serde_yaml::from_str(&content)?;
        
        let compiled_rule = self.compile_rule(rule)?;
        self.rules.push(compiled_rule);
        
        Ok(())
    }
    
    /// Compile a rule for efficient execution
    fn compile_rule(&self, rule: Rule) -> Result<CompiledRule, Box<dyn std::error::Error>> {
        let severity = match rule.severity.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Medium,
        };
        
        let mut compiled_patterns = Vec::new();
        
        for pattern in rule.patterns {
            let compiled_pattern = match pattern.pattern_type.as_str() {
                "contains" => CompiledPattern::Contains(pattern.pattern),
                "starts_with" => CompiledPattern::StartsWith(pattern.pattern),
                "ends_with" => CompiledPattern::EndsWith(pattern.pattern),
                "regex" => CompiledPattern::Regex(Regex::new(&pattern.pattern)?),
                _ => return Err(format!("Unsupported pattern type: {}", pattern.pattern_type).into()),
            };
            compiled_patterns.push(compiled_pattern);
        }
        
        Ok(CompiledRule {
            name: rule.name,
            description: rule.description,
            severity,
            patterns: compiled_patterns,
            file_types: rule.file_types,
            fix_suggestion: rule.fix_suggestion,
        })
    }
    
    /// Apply rules to content and return issues found
    pub fn apply_rules(
        &mut self,
        rules_dir: &Path,
        file_path: &Path,
        content: &str,
    ) -> Result<Vec<Issue>, Box<dyn std::error::Error>> {
        // Load rules if not already loaded
        if self.rules.is_empty() {
            self.load_rules_from_dir(rules_dir)?;
        }
        
        let mut issues = Vec::new();
        let file_type = detect_file_type_for_rules(file_path);
        
        for rule in &self.rules {
            // Check if rule applies to this file type
            if let Some(ref rule_file_types) = rule.file_types
                && !rule_file_types.contains(&file_type) {
                continue;
            }
            
            // Apply each pattern in the rule
            for pattern in &rule.patterns {
                let mut pattern_issues = self.find_pattern_matches(pattern, content, rule)?;
                issues.append(&mut pattern_issues);
            }
        }
        
        Ok(issues)
    }
    
    /// Find matches for a specific pattern
    fn find_pattern_matches(
        &self,
        pattern: &CompiledPattern,
        content: &str,
        rule: &CompiledRule,
    ) -> Result<Vec<Issue>, Box<dyn std::error::Error>> {
        let mut issues = Vec::new();
        
        match pattern {
            CompiledPattern::Contains(text) => {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(text) {
                        issues.push(Issue {
                            severity: rule.severity.clone(),
                            message: format!("{}: Pattern '{}' found", rule.description, text),
                            line: Some(line_num + 1),
                            rule: Some(rule.name.clone()),
                            suggestion: rule.fix_suggestion.clone(),
                        });
                    }
                }
            }
            CompiledPattern::StartsWith(text) => {
                for (line_num, line) in content.lines().enumerate() {
                    if line.trim_start().starts_with(text) {
                        issues.push(Issue {
                            severity: rule.severity.clone(),
                            message: format!("{}: Line starts with '{}'", rule.description, text),
                            line: Some(line_num + 1),
                            rule: Some(rule.name.clone()),
                            suggestion: rule.fix_suggestion.clone(),
                        });
                    }
                }
            }
            CompiledPattern::EndsWith(text) => {
                for (line_num, line) in content.lines().enumerate() {
                    if line.trim_end().ends_with(text) {
                        issues.push(Issue {
                            severity: rule.severity.clone(),
                            message: format!("{}: Line ends with '{}'", rule.description, text),
                            line: Some(line_num + 1),
                            rule: Some(rule.name.clone()),
                            suggestion: rule.fix_suggestion.clone(),
                        });
                    }
                }
            }
            CompiledPattern::Regex(regex) => {
                for (line_num, line) in content.lines().enumerate() {
                    if regex.is_match(line) {
                        issues.push(Issue {
                            severity: rule.severity.clone(),
                            message: format!("{}: Regex pattern matched", rule.description),
                            line: Some(line_num + 1),
                            rule: Some(rule.name.clone()),
                            suggestion: rule.fix_suggestion.clone(),
                        });
                    }
                }
            }
        }
        
        Ok(issues)
    }
}

fn detect_file_type_for_rules(path: &Path) -> String {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        extension.to_lowercase()
    } else {
        "unknown".to_string()
    }
}