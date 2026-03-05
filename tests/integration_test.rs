use vow::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use serde_json;

/// Test: AI-generated code file should flag multiple issues
#[test]
fn test_ai_generated_code_detection() {
    let ai_code_path = PathBuf::from("tests/fixtures/ai_code.py");
    let result = analyze_file(&ai_code_path).unwrap();
    
    assert_eq!(result.file_type, FileType::Python);
    assert!(result.issues.len() > 5, "AI code should have multiple issues, got {}", result.issues.len());
    
    // Should detect hallucinated imports
    let has_hallucinated_imports = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("hallucinated")) || 
        i.message.contains("unknown") || 
        i.message.contains("fictional") ||
        i.message.contains("magic_api") ||
        i.message.contains("impossible_lib"));
    
    // Should detect hardcoded secrets
    let has_hardcoded_secrets = result.issues.iter().any(|i| 
        i.message.contains("API key") || 
        i.message.contains("hardcoded") ||
        i.message.contains("secret") ||
        i.message.contains("password"));
    
    // Should detect dangerous eval usage
    let has_eval_usage = result.issues.iter().any(|i| 
        i.message.contains("eval"));
    
    // Should detect dangerous system calls
    let has_system_calls = result.issues.iter().any(|i| 
        i.message.contains("system call") || 
        i.message.contains("rm -rf") ||
        i.message.contains("dangerous"));
    
    assert!(has_hallucinated_imports, "Should detect hallucinated imports");
    assert!(has_hardcoded_secrets, "Should detect hardcoded secrets");
    assert!(has_eval_usage, "Should detect dangerous eval usage");
    assert!(has_system_calls, "Should detect dangerous system calls");
    
    // Trust score should be very low due to multiple serious issues  
    assert!(result.trust_score <= 10, "AI-generated code with security issues should have very low trust score, got {}", result.trust_score);
}

/// Test: Clean human code file should have high trust score and minimal flags
#[test]
fn test_clean_human_code_high_trust() {
    let human_code_path = PathBuf::from("tests/fixtures/human_code.py");
    let result = analyze_file(&human_code_path).unwrap();
    
    assert_eq!(result.file_type, FileType::Python);
    
    // Should have very few issues (clean human code) - allow for some false positives
    let serious_issues_count = result.issues.iter()
        .filter(|i| matches!(i.severity, Severity::High | Severity::Critical))
        .count();
    
    assert!(serious_issues_count <= 2, "Clean human code should have minimal serious issues, got {}", serious_issues_count);
    
    // Should not flag standard library imports as hallucinated
    let has_false_hallucination = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("hallucinated")) &&
        (i.message.contains("os") || i.message.contains("json") || i.message.contains("pathlib")));
    
    assert!(!has_false_hallucination, "Should not flag standard library imports as hallucinated");
    
    // Trust score should be reasonably high for clean human code (adjusted for real-world detection)
    assert!(result.trust_score >= 70, "Clean human code should have reasonably high trust score, got {}", result.trust_score);
}

/// Test: AI-generated text should be detected with confidence scoring
#[test]
fn test_ai_generated_text_detection_with_confidence() {
    let ai_text_path = PathBuf::from("tests/fixtures/ai_text.md");
    let result = analyze_file(&ai_text_path).unwrap();
    
    assert_eq!(result.file_type, FileType::Markdown);
    assert!(result.issues.len() > 3, "AI text should have multiple detection issues");
    
    // Should detect AI self-identification
    let has_ai_identity = result.issues.iter().any(|i| 
        i.message.contains("AI") && i.message.contains("language model"));
    
    // Should detect AI transition phrases
    let has_transition_phrases = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("transition_phrases")) ||
        i.message.contains("Furthermore") ||
        i.message.contains("Moreover") ||
        i.message.contains("Having said that"));
    
    // Should detect AI emphasis patterns
    let has_emphasis_phrases = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("emphasis_phrases")) ||
        i.message.contains("it's important to note") ||
        i.message.contains("it cannot be overstated"));
    
    // Should detect AI buzzwords
    let has_ai_buzzwords = result.issues.iter().any(|i| 
        i.message.contains("cutting-edge") ||
        i.message.contains("state-of-the-art") ||
        i.message.contains("comprehensive") ||
        i.message.contains("multifaceted"));
    
    // Should provide confidence scoring
    let has_confidence_score = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("confidence")));
    
    assert!(has_ai_identity, "Should detect AI self-identification");
    assert!(has_transition_phrases, "Should detect AI transition phrases");
    assert!(has_emphasis_phrases, "Should detect AI emphasis phrases");
    assert!(has_ai_buzzwords, "Should detect AI buzzwords");
    assert!(has_confidence_score, "Should provide confidence scoring");
    
    // Trust score should be very low due to strong AI patterns
    assert!(result.trust_score <= 10, "AI-generated text should have very low trust score, got {}", result.trust_score);
}

/// Test: Human-written text should NOT be flagged as AI
#[test]
fn test_human_text_not_flagged_as_ai() {
    let human_text_path = PathBuf::from("tests/fixtures/human_text.md");
    let result = analyze_file(&human_text_path).unwrap();
    
    assert_eq!(result.file_type, FileType::Markdown);
    
    // Should have very few AI detection issues
    let ai_detection_issues = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| 
            r.contains("ai_") || 
            r.contains("confidence") ||
            r.contains("transition_phrases") ||
            r.contains("emphasis_phrases")))
        .count();
    
    assert!(ai_detection_issues <= 2, "Natural human text should have minimal AI detection flags, got {} issues", ai_detection_issues);
    
    // Should not detect AI self-identification
    let has_ai_identity = result.issues.iter().any(|i| 
        i.message.contains("AI") && i.message.contains("language model"));
    
    assert!(!has_ai_identity, "Human text should not be flagged for AI self-identification");
    
    // Trust score should be high for natural human writing
    assert!(result.trust_score >= 90, "Natural human text should have very high trust score, got {}", result.trust_score);
}

/// Test: Directory scan respects .vowignore exclusions
#[test]
fn test_vowignore_exclusions_respected() {
    let temp_dir = TempDir::new().unwrap();
    
    // Copy .vowignore file to test directory
    let vowignore_source = PathBuf::from("tests/fixtures/.vowignore");
    let vowignore_dest = temp_dir.path().join(".vowignore");
    fs::copy(vowignore_source, vowignore_dest).unwrap();
    
    // Create test directory structure that should be excluded
    let test_dir = temp_dir.path().join("tests");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("should_be_excluded.py"), "# This should be excluded").unwrap();
    
    // Create excluded file as specified in .vowignore
    fs::write(temp_dir.path().join("excluded_file.py"), "# This should be excluded").unwrap();
    
    // Create a .test.py file that should be excluded
    fs::write(temp_dir.path().join("unit.test.py"), "# This should be excluded").unwrap();
    
    // Create files that should NOT be excluded
    fs::write(temp_dir.path().join("main.py"), "print('should be included')").unwrap();
    fs::write(temp_dir.path().join("utils.py"), "def helper(): pass").unwrap();
    
    // Analyze the directory
    let results = analyze_directory(temp_dir.path()).unwrap();
    
    // Should only find main.py and utils.py, excluding the test files
    assert_eq!(results.len(), 2, "Expected 2 files, but got {}", results.len());
    
    let found_files: Vec<&str> = results.iter()
        .map(|r| r.path.file_name().unwrap().to_str().unwrap())
        .collect();
    
    assert!(found_files.contains(&"main.py"), "Should include main.py");
    assert!(found_files.contains(&"utils.py"), "Should include utils.py");
    assert!(!found_files.contains(&"should_be_excluded.py"), "Should exclude test directory files");
    assert!(!found_files.contains(&"excluded_file.py"), "Should exclude explicitly ignored file");
    assert!(!found_files.contains(&"unit.test.py"), "Should exclude .test.py files");
}

/// Test: --format json produces valid JSON output
#[test]
fn test_json_format_output() {
    // Create a temporary file to test
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("test.py"), "print('hello world')").unwrap();
    
    // Run vow check with JSON format
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    
    // Verify the output is valid JSON
    let json_result: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    
    assert!(json_result.is_ok(), "JSON output should be valid, got error: {:?}\nOutput: {}", 
           json_result.err(), stdout);
    
    let json_data = json_result.unwrap();
    
    // Verify expected JSON structure
    assert!(json_data.get("files").is_some(), "JSON should have 'files' field");
    assert!(json_data.get("summary").is_some(), "JSON should have 'summary' field");
    
    let summary = json_data.get("summary").unwrap();
    assert!(summary.get("total_files").is_some(), "Summary should have 'total_files' field");
    assert!(summary.get("avg_score").is_some(), "Summary should have 'avg_score' field");
    assert!(summary.get("total_issues").is_some(), "Summary should have 'total_issues' field");
}

/// Test: --quiet suppresses per-file output
#[test]
fn test_quiet_mode_suppresses_output() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create multiple files to generate verbose output normally
    fs::write(temp_dir.path().join("file1.py"), "print('test1')").unwrap();
    fs::write(temp_dir.path().join("file2.py"), "print('test2')").unwrap();
    fs::write(temp_dir.path().join("file3.py"), "print('test3')").unwrap();
    
    // Run vow check in quiet mode
    let quiet_output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--quiet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    // Run vow check in normal mode for comparison
    let normal_output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(temp_dir.path().to_str().unwrap())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    let quiet_stdout = String::from_utf8(quiet_output.stdout).unwrap();
    let normal_stdout = String::from_utf8(normal_output.stdout).unwrap();
    
    // Quiet mode should have significantly less output
    assert!(quiet_stdout.len() < normal_stdout.len(), 
           "Quiet mode should have less output. Quiet: {} chars, Normal: {} chars", 
           quiet_stdout.len(), normal_stdout.len());
    
    // Quiet mode should not contain scanning progress messages
    assert!(!quiet_stdout.contains("Scanning directory"), 
           "Quiet mode should not show scanning messages");
    
    // But should still contain the final performance summary
    assert!(quiet_stdout.contains("Performance Summary") || 
           quiet_stdout.contains("Total files analyzed"), 
           "Quiet mode should still show final summary");
}

/// Additional test: Verify CLI integration with various file types
#[test]
fn test_cli_integration_multiple_file_types() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create files of different types
    fs::write(temp_dir.path().join("script.py"), "import os\nprint('python')").unwrap();
    fs::write(temp_dir.path().join("app.js"), "console.log('javascript');").unwrap();
    fs::write(temp_dir.path().join("README.md"), "# This is a markdown file\n\nIt contains documentation.").unwrap();
    fs::write(temp_dir.path().join("config.json"), r#"{"name": "test", "version": "1.0"}"#).unwrap();
    
    // Run analysis
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    assert!(output.status.success(), "Command should succeed");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json_data: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    
    let files = json_data.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 4, "Should analyze all 4 files");
    
    // Verify different file types were detected correctly
    let file_types: Vec<String> = files.iter()
        .map(|f| f.get("file_type").unwrap().as_str().unwrap().to_string())
        .collect();
    
    assert!(file_types.contains(&"Python".to_string()));
    assert!(file_types.contains(&"JavaScript".to_string()));
    assert!(file_types.contains(&"Markdown".to_string()));
    assert!(file_types.contains(&"JSON".to_string()));
}

/// Test: Verify exit codes work correctly
#[test]
fn test_exit_codes() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a clean file that should pass threshold
    fs::write(temp_dir.path().join("clean.py"), "# Clean code\nprint('hello')").unwrap();
    
    // Run with high threshold - should succeed (exit code 0)
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--threshold")
        .arg("50")
        .arg("--quiet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    assert!(output.status.success(), "Should succeed with low threshold");
    
    // Test with problematic file and high threshold - should fail
    fs::write(temp_dir.path().join("bad.py"), "eval('malicious code')\nAPI_KEY = 'secret123'").unwrap();
    
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--threshold")
        .arg("90")
        .arg("--quiet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    assert!(!output.status.success(), "Should fail with high threshold and problematic files");
}

/// Test: Single file analysis
#[test]
fn test_single_file_analysis() {
    let human_code_path = "tests/fixtures/human_code.py";
    
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("check")
        .arg(human_code_path)
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run vow command");
    
    assert!(output.status.success(), "Single file analysis should succeed");
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json_data: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    
    let files = json_data.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 1, "Should analyze exactly one file");
    
    let file = &files[0];
    assert_eq!(file.get("file_type").unwrap().as_str().unwrap(), "Python");
}