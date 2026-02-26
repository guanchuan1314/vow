use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use vow::{check_input, Issue, Severity, AnalysisResult, FileType, fix::engine};

#[test]
fn test_fix_suggestions_basic() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.py");
    
    // Create a file with a hallucinated import
    let content = r#"import nonexistent_package
print("Hello world")
"#;
    fs::write(&file_path, content).unwrap();
    
    // Analyze the file to get issues with fix suggestions
    let exit_code = check_input(
        file_path.to_str().unwrap().to_string(),
        Some(vec!["json".to_string()]),
        None,
        None,
        None,
        None,
        Some(true), // quiet
        None,
        true, // no_config
        None,
        None,
        false,
        false,
        false,
        10,
        20,
        100,
        true, // no_cache
        false,
        false,
        false, // no baseline
        false, // no fix
        true,  // suggest
    );
    
    // Should complete successfully even with issues
    assert_eq!(exit_code.unwrap(), 0);
}

#[test]
fn test_apply_fixes() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.py");
    
    // Create a file with a hallucinated import that should be removed
    let content = r#"import nonexistent_package
import os
print("Hello world")
"#;
    fs::write(&file_path, content).unwrap();
    
    // Test fix application
    let mut issue_with_fix = Issue {
        severity: Severity::Medium,
        message: "Hallucinated import".to_string(),
        line: Some(1),
        rule: Some("hallucinated_api".to_string()),
        suggestion: Some("REMOVE_LINE".to_string()),
    };
    
    let mut result = AnalysisResult {
        path: file_path.clone(),
        file_type: FileType::Python,
        issues: vec![issue_with_fix],
        trust_score: 75,
    };
    
    // Apply fixes
    let fixed_count = engine::apply_fixes(&mut [result], false).unwrap();
    assert_eq!(fixed_count, 1);
    
    // Verify the file content
    let new_content = fs::read_to_string(&file_path).unwrap();
    assert!(!new_content.contains("nonexistent_package"));
    assert!(new_content.contains("import os"));
    assert!(new_content.contains("print(\"Hello world\")"));
}

#[test]
fn test_fix_suggestion_patterns() {
    // Test different fix patterns
    assert_eq!(
        engine::parse_fix_suggestion("REMOVE_LINE", ""),
        Some(String::new())
    );
    
    assert_eq!(
        engine::parse_fix_suggestion("REPLACE: old -> new", ""),
        Some("new".to_string())
    );
    
    assert_eq!(
        engine::parse_fix_suggestion("REPLACE_WITH: fixed_code", ""),
        Some("fixed_code".to_string())
    );
}

#[test]
fn test_suggest_mode() {
    // Test that suggestions are shown but not applied
    let issue = Issue {
        severity: Severity::High,
        message: "Test issue".to_string(),
        line: Some(1),
        rule: Some("test_rule".to_string()),
        suggestion: Some("Fix suggestion".to_string()),
    };
    
    let result = AnalysisResult {
        path: PathBuf::from("test.py"),
        file_type: FileType::Python,
        issues: vec![issue],
        trust_score: 75,
    };
    
    // This should not panic
    engine::show_suggestions(&[result]);
}