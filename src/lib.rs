pub mod analyzers;
pub mod rules;
pub mod report;

use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Read};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub file_type: FileType,
    pub issues: Vec<Issue>,
    pub trust_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub message: String,
    pub line: Option<usize>,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileType {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Markdown,
    Text,
    YAML,
    JSON,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score_impact(&self) -> u8 {
        match self {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectResults {
    pub files: Vec<AnalysisResult>,
    pub summary: ProjectSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub total_files: usize,
    pub avg_score: u8,
    pub total_issues: usize,
    pub issues_by_severity: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub threshold: Option<u8>,
    pub enabled_analyzers: Option<Vec<String>>,
    pub custom_rule_dirs: Option<Vec<PathBuf>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            threshold: Some(70),
            enabled_analyzers: Some(vec!["code".to_string(), "text".to_string(), "rules".to_string()]),
            custom_rule_dirs: None,
        }
    }
}

/// Initialize a new Vow project
pub fn init_project(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let vow_dir = path.join(".vow");
    
    // Create .vow directory
    fs::create_dir_all(&vow_dir)?;
    
    // Create config.yaml
    let config = Config::default();
    let config_content = serde_yaml::to_string(&config)?;
    fs::write(vow_dir.join("config.yaml"), config_content)?;
    
    // Create rules directory with example rules
    let rules_dir = vow_dir.join("rules");
    fs::create_dir_all(&rules_dir)?;
    
    let example_rule = r#"name: "hardcoded_passwords"
description: "Detect hardcoded passwords in code"
severity: "high"
patterns:
  - type: "regex"
    pattern: "password\\s*=\\s*[\"'][^\"']+[\"']"
  - type: "contains"
    pattern: "SECRET_KEY = "
file_types: ["py", "js", "ts"]
"#;
    fs::write(rules_dir.join("security.yaml"), example_rule)?;
    
    println!("✓ Initialized Vow project in {}", path.display());
    println!("  - Created .vow/config.yaml");
    println!("  - Created .vow/rules/security.yaml");
    
    Ok(())
}

/// Main entry point for checking input (file, directory, or stdin)
pub fn check_input(
    path: String,
    format: String,
    rules: Option<PathBuf>,
    threshold: Option<u8>,
    ci: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut final_format = format;
    
    // CI mode implies JSON output
    if ci {
        final_format = "json".to_string();
    }
    
    let results = if path == "-" {
        // Read from stdin
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        let stdin_path = PathBuf::from("<stdin>");
        vec![analyze_content(&stdin_path, &buffer)?]
    } else {
        let path_buf = PathBuf::from(&path);
        if path_buf.is_file() {
            vec![analyze_file(&path_buf)?]
        } else if path_buf.is_dir() {
            analyze_directory(&path_buf)?
        } else {
            return Err(format!("Path does not exist: {}", path).into());
        }
    };
    
    // Load config
    let config = load_config(&PathBuf::from(".")).unwrap_or_default();
    
    // Apply rules to all results
    let mut final_results = Vec::new();
    for mut result in results {
        result = apply_rules_to_result(result, &rules)?;
        final_results.push(result);
    }
    
    // Calculate project summary
    let project_results = calculate_project_summary(final_results);
    
    // Generate report
    generate_report(&project_results, &final_format)?;
    
    // Check threshold for exit code
    let effective_threshold = threshold.or(config.threshold).unwrap_or(70);
    if project_results.summary.avg_score < effective_threshold {
        Ok(1) // Exit code 1 for failure
    } else {
        Ok(0) // Exit code 0 for success
    }
}

/// Analyze a single file
pub fn analyze_file(path: &Path) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    analyze_content(path, &content)
}

/// Analyze content with a given path context
pub fn analyze_content(path: &Path, content: &str) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let file_type = detect_file_type(path);
    let mut issues = Vec::new();
    
    // Run appropriate analyzers based on file type
    match file_type {
        FileType::Python | FileType::JavaScript | FileType::TypeScript => {
            // Load custom allowlist if available
            let custom_allowlist = analyzers::code::CodeAnalyzer::load_custom_allowlist();
            let code_analyzer = analyzers::code::CodeAnalyzer::with_custom_allowlist(custom_allowlist);
            let mut result = code_analyzer.analyze(path, content);
            issues.append(&mut result.issues);
        }
        FileType::Markdown | FileType::Text => {
            let text_analyzer = analyzers::text::TextAnalyzer::new();
            let mut result = text_analyzer.analyze(path, content);
            issues.append(&mut result.issues);
        }
        _ => {} // No specific analyzer for this file type
    }
    
    // Calculate trust score
    let trust_score = calculate_trust_score(&issues);
    
    Ok(AnalysisResult {
        path: path.to_path_buf(),
        file_type,
        issues,
        trust_score,
    })
}

/// Analyze all supported files in a directory
pub fn analyze_directory(path: &Path) -> Result<Vec<AnalysisResult>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    
    // Create walker with default exclusions and .vowignore support
    let mut walker = WalkBuilder::new(path);
    walker
        .hidden(false) // Don't automatically skip hidden files
        .git_ignore(true) // Respect .gitignore
        .git_global(false) // Don't use global git config
        .git_exclude(false); // Don't use .git/info/exclude
    
    // Add default directory exclusions
    let default_excludes = [
        "node_modules", ".git", "dist", "build", "target", ".vow", 
        "__pycache__", ".next", ".nuxt", "vendor", "coverage", 
        ".tox", ".venv", "venv", "env", ".env"
    ];
    
    walker.filter_entry(move |entry| {
        if entry.file_type().map_or(false, |ft| ft.is_dir()) {
            let name = entry.file_name().to_string_lossy();
            !default_excludes.contains(&name.as_ref())
        } else {
            true
        }
    });
    
    // Add .vowignore file support
    walker.add_custom_ignore_filename(".vowignore");
    
    for result in walker.build() {
        match result {
            Ok(entry) => {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let file_path = entry.path();
                    if is_supported_file(file_path) {
                        match analyze_file(file_path) {
                            Ok(result) => results.push(result),
                            Err(e) => eprintln!("Warning: Failed to analyze {}: {}", file_path.display(), e),
                        }
                    }
                }
            }
            Err(e) => eprintln!("Warning: Error walking directory: {}", e),
        }
    }
    
    Ok(results)
}

/// Apply rules to a single analysis result
fn apply_rules_to_result(
    mut result: AnalysisResult,
    rules_path: &Option<PathBuf>,
) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let rules_dir = rules_path
        .clone()
        .or_else(|| Some(PathBuf::from(".vow/rules")))
        .unwrap();
    
    if rules_dir.exists() {
        let mut rule_engine = rules::engine::RuleEngine::new();
        let rule_issues = rule_engine.apply_rules(&rules_dir, &result.path, &fs::read_to_string(&result.path).unwrap_or_default())?;
        result.issues.extend(rule_issues);
        
        // Recalculate trust score with rule results
        result.trust_score = calculate_trust_score(&result.issues);
    }
    
    Ok(result)
}

/// Calculate trust score from issues
fn calculate_trust_score(issues: &[Issue]) -> u8 {
    let mut score = 100u8;
    
    for issue in issues {
        score = score.saturating_sub(issue.severity.score_impact());
    }
    
    score
}

/// Calculate project-level summary
fn calculate_project_summary(results: Vec<AnalysisResult>) -> ProjectResults {
    let total_files = results.len();
    let total_issues: usize = results.iter().map(|r| r.issues.len()).sum();
    let avg_score = if total_files > 0 {
        results.iter().map(|r| r.trust_score as u32).sum::<u32>() / total_files as u32
    } else {
        100
    } as u8;
    
    let mut issues_by_severity = std::collections::HashMap::new();
    for result in &results {
        for issue in &result.issues {
            let severity_str = format!("{:?}", issue.severity).to_lowercase();
            *issues_by_severity.entry(severity_str).or_insert(0) += 1;
        }
    }
    
    ProjectResults {
        files: results,
        summary: ProjectSummary {
            total_files,
            avg_score,
            total_issues,
            issues_by_severity,
        },
    }
}

/// Load configuration from .vow/config.yaml
fn load_config(project_root: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = project_root.join(".vow/config.yaml");
    if config_path.exists() {
        let content = fs::read_to_string(config_path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

/// Generate report in specified format
fn generate_report(
    results: &ProjectResults,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "terminal" => report::terminal::print_terminal_report(results),
        "json" => report::json::print_json_report(results)?,
        "sarif" => report::sarif::print_sarif_report(results)?,
        _ => return Err(format!("Unsupported format: {}", format).into()),
    }
    
    Ok(())
}

/// Detect file type from path
pub fn detect_file_type(path: &Path) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension.to_lowercase().as_str() {
            "py" => FileType::Python,
            "js" | "jsx" => FileType::JavaScript,
            "ts" | "tsx" => FileType::TypeScript,
            "rs" => FileType::Rust,
            "md" => FileType::Markdown,
            "txt" => FileType::Text,
            "yaml" | "yml" => FileType::YAML,
            "json" => FileType::JSON,
            _ => FileType::Text,
        }
    } else {
        FileType::Unknown
    }
}

/// Check if file is supported for analysis
fn is_supported_file(path: &Path) -> bool {
    matches!(
        detect_file_type(path),
        FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Rust
            | FileType::Markdown
            | FileType::Text
            | FileType::YAML
            | FileType::JSON
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trust_score_calculation() {
        let issues = vec![
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(1),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::High,
                message: "High issue".to_string(),
                line: Some(2),
                rule: Some("test".to_string()),
            },
        ];
        
        let score = calculate_trust_score(&issues);
        assert_eq!(score, 60); // 100 - 25 - 15 = 60
    }
    
    #[test]
    fn test_trust_score_floor() {
        let issues = vec![
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(1),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(2),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(3),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(4),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(5),
                rule: Some("test".to_string()),
            },
        ];
        
        let score = calculate_trust_score(&issues);
        assert_eq!(score, 0); // Floor at 0
    }
    
    #[test]
    fn test_file_type_detection() {
        assert_eq!(detect_file_type(&PathBuf::from("test.py")), FileType::Python);
        assert_eq!(detect_file_type(&PathBuf::from("test.js")), FileType::JavaScript);
        assert_eq!(detect_file_type(&PathBuf::from("test.ts")), FileType::TypeScript);
        assert_eq!(detect_file_type(&PathBuf::from("test.rs")), FileType::Rust);
        assert_eq!(detect_file_type(&PathBuf::from("test.md")), FileType::Markdown);
    }
    
    #[test]
    fn test_analyze_content_python() {
        let content = r#"
import os
eval("print('hello')")
API_KEY = "secret123"
"#;
        let result = analyze_content(&PathBuf::from("test.py"), content).unwrap();
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        // Should detect eval usage and hardcoded API key
        let has_eval = result.issues.iter().any(|i| i.message.contains("eval"));
        let has_api_key = result.issues.iter().any(|i| i.message.contains("API key"));
        
        assert!(has_eval);
        assert!(has_api_key);
    }
    
    #[test]
    fn test_analyze_content_markdown() {
        let content = r#"
# Test Document

As an AI, I cannot provide specific details. However, it's important to note that 
this comprehensive analysis delves into the multifaceted aspects.
"#;
        let result = analyze_content(&PathBuf::from("test.md"), content).unwrap();
        
        assert_eq!(result.file_type, FileType::Markdown);
        assert!(result.issues.len() > 0);
        
        // Should detect AI patterns
        let has_ai_pattern = result.issues.iter().any(|i| i.message.contains("AI"));
        assert!(has_ai_pattern);
    }

    #[test]
    fn test_expanded_packages_not_flagged() {
        // Test Python packages
        let python_content = r#"
import fastapi
import pydantic
import uvicorn
from starlette import applications
import httpx
import prisma
"#;
        let result = analyze_content(&PathBuf::from("test.py"), python_content).unwrap();
        
        // Should not flag these as hallucinated since they're in our expanded allowlist
        let has_hallucination = result.issues.iter().any(|i| i.rule.as_ref().map_or(false, |r| r == "hallucinated_api"));
        assert!(!has_hallucination);
        
        // Test JavaScript packages
        let js_content = r#"
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { TRPCError } from '@trpc/server';
import fastify from 'fastify';
import next from 'next';
"#;
        let result = analyze_content(&PathBuf::from("test.js"), js_content).unwrap();
        
        // Should not flag these as hallucinated since they're in our expanded allowlist
        let has_hallucination = result.issues.iter().any(|i| i.rule.as_ref().map_or(false, |r| r == "hallucinated_api"));
        assert!(!has_hallucination);
    }

    #[test]
    fn test_custom_allowlist() {
        use std::fs;
        use tempfile::TempDir;
        use std::env;
        
        let temp_dir = TempDir::new().unwrap();
        let vow_dir = temp_dir.path().join(".vow");
        fs::create_dir_all(&vow_dir).unwrap();
        
        // Create custom allowlist
        let custom_allowlist = r#"python:
  - my_internal_lib
  - company_utils
javascript:
  - "@company/ui-kit"
  - internal-logger
"#;
        fs::write(vow_dir.join("known-packages.yaml"), custom_allowlist).unwrap();
        
        // Change to temp directory
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();
        
        // Test Python custom package
        let python_content = "import my_internal_lib\nfrom company_utils import helper";
        let result = analyze_content(&PathBuf::from("test.py"), python_content).unwrap();
        
        // Should not flag custom packages as hallucinated
        let has_hallucination = result.issues.iter().any(|i| {
            i.rule.as_ref().map_or(false, |r| r == "hallucinated_api") &&
            (i.message.contains("my_internal_lib") || i.message.contains("company_utils"))
        });
        assert!(!has_hallucination);
        
        // Test JavaScript custom package
        let js_content = r#"import { Button } from '@company/ui-kit';"#;
        let result = analyze_content(&PathBuf::from("test.js"), js_content).unwrap();
        
        let has_hallucination = result.issues.iter().any(|i| {
            i.rule.as_ref().map_or(false, |r| r == "hallucinated_api") &&
            i.message.contains("@company/ui-kit")
        });
        assert!(!has_hallucination);
        
        // Restore original directory
        env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_directory_exclusions() {
        use std::fs;
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        
        // Create directories that should be excluded
        let node_modules = temp_dir.path().join("node_modules");
        fs::create_dir_all(&node_modules).unwrap();
        fs::write(node_modules.join("test.js"), "console.log('should be excluded');").unwrap();
        
        let git_dir = temp_dir.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join("config"), "# git config").unwrap();
        
        let target_dir = temp_dir.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("debug.rs"), "// rust debug file").unwrap();
        
        // Create a file that should be included
        fs::write(temp_dir.path().join("main.js"), "console.log('should be included');").unwrap();
        
        // Analyze the directory
        let results = analyze_directory(temp_dir.path()).unwrap();
        
        // Should only find main.js, not the excluded files
        assert_eq!(results.len(), 1);
        assert!(results[0].path.file_name().unwrap() == "main.js");
    }
}