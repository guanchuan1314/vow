use vow::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_known_ai_generated_code_detection() {
    // Test with the existing AI-generated test file
    let result = analyze_file(&PathBuf::from("test_ai_code.py")).unwrap();
    
    assert_eq!(result.file_type, FileType::Python);
    assert!(result.issues.len() > 0);
    
    // Should detect multiple security issues
    let has_hardcoded_secret = result.issues.iter().any(|i| 
        i.message.contains("API key") || i.message.contains("hardcoded"));
    let has_eval_usage = result.issues.iter().any(|i| 
        i.message.contains("eval"));
    let has_system_call = result.issues.iter().any(|i| 
        i.message.contains("System call") || i.message.contains("rm -rf"));
    let has_dangerous_commands = result.issues.iter().any(|i| 
        i.message.contains("rm -rf"));
    
    assert!(has_hardcoded_secret, "Should detect hardcoded secrets");
    assert!(has_eval_usage, "Should detect dangerous eval usage");
    assert!(has_system_call, "Should detect dangerous system calls");
    assert!(has_dangerous_commands, "Should detect dangerous commands");
    
    // Trust score should be low due to multiple issues
    assert!(result.trust_score < 70, "Trust score should be low for AI-generated code with security issues");
}

#[test]
fn test_known_human_code_should_not_flag() {
    let human_code = r#"#!/usr/bin/env python3
"""
A simple calculator module for basic arithmetic operations.
Written by human developer for educational purposes.
"""

import math


def add(a, b):
    """Add two numbers and return the result."""
    return a + b


def subtract(a, b):
    """Subtract b from a and return the result."""
    return a - b


def multiply(a, b):
    """Multiply two numbers and return the result."""
    return a * b


def divide(a, b):
    """Divide a by b and return the result. Raises ZeroDivisionError if b is 0."""
    if b == 0:
        raise ZeroDivisionError("Cannot divide by zero")
    return a / b


def main():
    """Simple interactive calculator."""
    print("Simple Calculator")
    while True:
        try:
            operation = input("Enter operation (+, -, *, /) or 'quit': ").strip()
            if operation.lower() == 'quit':
                break
            
            if operation in ['+', '-', '*', '/']:
                num1 = float(input("Enter first number: "))
                num2 = float(input("Enter second number: "))
                
                if operation == '+':
                    result = add(num1, num2)
                elif operation == '-':
                    result = subtract(num1, num2)
                elif operation == '*':
                    result = multiply(num1, num2)
                elif operation == '/':
                    result = divide(num1, num2)
                
                print(f"Result: {result}")
            else:
                print("Invalid operation")
        except (ValueError, ZeroDivisionError) as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
"#;

    let temp_dir = TempDir::new().unwrap();
    let human_file = temp_dir.path().join("calculator.py");
    fs::write(&human_file, human_code).unwrap();
    
    let result = analyze_file(&human_file).unwrap();
    
    assert_eq!(result.file_type, FileType::Python);
    
    // Should have very few or no AI detection issues
    let ai_issues_count = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| 
            r.contains("ai_") || r.contains("hallucinated") || r.contains("confidence")))
        .count();
    
    assert!(ai_issues_count <= 2, "Human code should have minimal AI detection flags, got {} issues", ai_issues_count);
    
    // Trust score should be high for clean human code
    assert!(result.trust_score > 85, "Human code should have high trust score, got {}", result.trust_score);
}

#[test]
fn test_known_ai_generated_text_detection() {
    // Test with the existing AI-generated text file
    let result = analyze_file(&PathBuf::from("test_ai_text.md")).unwrap();
    
    assert_eq!(result.file_type, FileType::Markdown);
    assert!(result.issues.len() > 0);
    
    // Should detect AI patterns
    let has_ai_identity = result.issues.iter().any(|i| 
        i.message.contains("AI self-identification"));
    let has_ai_phrases = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("ai_")) &&
        i.message.contains("AI"));
    let has_unsourced_claims = result.issues.iter().any(|i| 
        i.message.contains("factual claim without"));
    let has_ai_buzzwords = result.issues.iter().any(|i| 
        i.message.contains("buzzword") || i.message.contains("cutting-edge"));
    
    assert!(has_ai_identity, "Should detect AI self-identification");
    assert!(has_ai_phrases, "Should detect AI writing patterns"); 
    assert!(has_unsourced_claims, "Should detect unsourced claims");
    assert!(has_ai_buzzwords, "Should detect AI buzzwords");
    
    // Trust score should be low due to AI patterns
    assert!(result.trust_score < 60, "AI-generated text should have low trust score");
}

#[test]
fn test_human_text_should_not_flag() {
    let human_text = r#"# Personal Blog Post

## My Weekend Adventure

Last Saturday, I decided to go hiking with my friends. The weather was perfect - sunny but not too hot. 

We started early in the morning and took the trail through Miller Park. The views were amazing, especially from the ridge overlooking the valley.

My favorite part was when we stopped for lunch by the small creek. We sat on the rocks and shared sandwiches while listening to the water flow. 

On the way back, we took some great photos. I'm already planning our next hike for next month. Maybe we'll try the longer trail that leads to the waterfall.

Overall, it was a wonderful day spent in nature with good friends. Sometimes the simple things in life are the most rewarding.
"#;

    let temp_dir = TempDir::new().unwrap();
    let human_file = temp_dir.path().join("blog_post.md");
    fs::write(&human_file, human_text).unwrap();
    
    let result = analyze_file(&human_file).unwrap();
    
    assert_eq!(result.file_type, FileType::Markdown);
    
    // Should have very few AI detection issues
    let ai_issues_count = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| 
            r.contains("ai_") || r.contains("sentence_structure") || r.contains("confidence")))
        .count();
    
    assert!(ai_issues_count <= 1, "Natural human text should have minimal AI flags, got {} issues", ai_issues_count);
    
    // Trust score should be high
    assert!(result.trust_score > 90, "Natural human text should have high trust score, got {}", result.trust_score);
}

#[test]
fn test_vowignore_exclusions() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create directory structure with files that should be excluded
    let test_dir = temp_dir.path().join("tests");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("test_file.py"), "# test file that should be excluded").unwrap();
    
    let node_modules = temp_dir.path().join("node_modules");
    fs::create_dir_all(&node_modules).unwrap();
    fs::write(node_modules.join("package.js"), "// should be excluded").unwrap();
    
    // Create .vowignore file
    let vowignore_content = r#"**/tests/**
**/node_modules/**
*.test.py
"#;
    fs::write(temp_dir.path().join(".vowignore"), vowignore_content).unwrap();
    
    // Create a file that should NOT be excluded
    fs::write(temp_dir.path().join("main.py"), "print('should be included')").unwrap();
    
    // Analyze the directory
    let results = analyze_directory(temp_dir.path()).unwrap();
    
    // Should only find main.py, excluding the test files and node_modules
    assert_eq!(results.len(), 1);
    assert!(results[0].path.file_name().unwrap() == "main.py");
}

#[test]
fn test_cli_flags_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("test.py"), "print('hello')").unwrap();
    
    // Test quiet mode (this mainly tests that it doesn't panic)
    let (results, _metrics) = analyze_directory_parallel(
        temp_dir.path(),
        false, // verbose
        true,  // quiet
        10,    // max_file_size_mb
        10,    // max_depth
        100,   // max_issues
        false  // no_cache
    ).unwrap();
    
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].file_type, FileType::Python);
}

#[test]
fn test_cli_flags_verbose_mode() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("test.py"), "print('hello')").unwrap();
    
    // Test verbose mode (this mainly tests that it doesn't panic)
    let (results, _metrics) = analyze_directory_parallel(
        temp_dir.path(),
        true,  // verbose
        false, // quiet
        10,    // max_file_size_mb
        10,    // max_depth
        100,   // max_issues
        false  // no_cache
    ).unwrap();
    
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].file_type, FileType::Python);
}

#[test]
fn test_cli_flags_max_file_size_limit() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a small file
    fs::write(temp_dir.path().join("small.py"), "print('hello')").unwrap();
    
    // Create a "large" file (simulate by setting very small limit)
    fs::write(temp_dir.path().join("large.py"), "# This is a large file\n".repeat(1000)).unwrap();
    
    // Test with 1KB limit (very small)
    let (results, metrics) = analyze_directory_parallel(
        temp_dir.path(),
        false, // verbose
        true,  // quiet
        0,     // max_file_size_mb (0 means very small)
        10,    // max_depth
        100,   // max_issues
        false  // no_cache
    ).unwrap();
    
    // Both files should be skipped due to size limit being 0
    assert_eq!(results.len(), 0);
    assert!(metrics.files_skipped > 0);
    assert!(metrics.skipped_reasons.contains_key("too_large"));
}

#[test]
fn test_cli_flags_max_depth_limit() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create nested directories beyond max depth
    let deep_dir = temp_dir.path().join("level1/level2/level3/level4");
    fs::create_dir_all(&deep_dir).unwrap();
    fs::write(deep_dir.join("deep.py"), "print('deep file')").unwrap();
    
    // Create a file at root level
    fs::write(temp_dir.path().join("root.py"), "print('root file')").unwrap();
    
    // Test with max_depth = 2
    let (results, _metrics) = analyze_directory_parallel(
        temp_dir.path(),
        false, // verbose
        true,  // quiet
        10,    // max_file_size_mb
        2,     // max_depth (should exclude level3/level4/deep.py)
        100,   // max_issues
        false  // no_cache
    ).unwrap();
    
    // Should only find the root file, not the deeply nested one
    assert_eq!(results.len(), 1);
    assert!(results[0].path.file_name().unwrap() == "root.py");
}

#[test]
fn test_cli_flags_max_issues_per_file() {
    let problematic_code = r#"
eval("test1")
eval("test2") 
eval("test3")
eval("test4")
eval("test5")
API_KEY = "secret1"
API_SECRET = "secret2"
password = "secret3"
"#;
    
    let temp_dir = TempDir::new().unwrap();
    let problem_file = temp_dir.path().join("problems.py");
    fs::write(&problem_file, problematic_code).unwrap();
    
    // Test with max_issues = 3
    let result = analyze_file_with_limits(&problem_file, 3).unwrap();
    
    // Should have exactly 4 issues: 3 real issues + 1 limit warning
    assert_eq!(result.issues.len(), 4);
    
    // Should have the limit warning
    let has_limit_warning = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "max_issues_limit"));
    assert!(has_limit_warning, "Should have max issues limit warning");
}

#[test]
fn test_enhanced_text_analysis() {
    let ai_heavy_text = r#"
Moving forward, it's important to note that this comprehensive approach delves into the multifaceted aspects of the problem. That being said, the paradigm is nuanced and leverages cutting-edge methodologies.

On the other hand, this robust solution facilitates seamless integration. Having said that, it cannot be overstated that this sophisticated analysis provides optimal results.

With that in mind, the aforementioned techniques underscore the importance of holistic perspectives. In light of this, one cannot ignore the complex interplay of factors.

It's worth emphasizing that this intricate system utilizes state-of-the-art algorithms. More often than not, such comprehensive understanding leads to innovative solutions.
"#;
    
    let temp_dir = TempDir::new().unwrap();
    let ai_text_file = temp_dir.path().join("ai_heavy.md");
    fs::write(&ai_text_file, ai_heavy_text).unwrap();
    
    let result = analyze_file(&ai_text_file).unwrap();
    
    assert_eq!(result.file_type, FileType::Markdown);
    
    // Should detect multiple AI patterns
    let has_transition_phrases = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "ai_transition_phrases"));
    let has_emphasis_phrases = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "ai_emphasis_phrases"));
    let has_sentence_analysis = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "sentence_structure_analysis"));
    let has_confidence_score = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "ai_confidence_score"));
    
    assert!(has_transition_phrases, "Should detect AI transition phrases");
    assert!(has_emphasis_phrases, "Should detect AI emphasis phrases");
    assert!(has_sentence_analysis, "Should analyze sentence structure");
    assert!(has_confidence_score, "Should provide confidence score");
    
    // Trust score should be very low due to heavy AI patterns
    assert!(result.trust_score < 40, "Heavy AI text should have very low trust score, got {}", result.trust_score);
}

#[test]
fn test_enhanced_code_analysis() {
    let suspicious_code = r#"
def process_data(param1: str, param2: int, param3: float, param4: bool, param5: str, param6: int) -> Optional[Dict[str, Any]]:
    """Suspicious function with too many simple parameters."""
    return None

def get_delete_user():  # Contradictory naming
    """This function name doesn't make sense."""
    pass

# Type confusion examples
result = "hello" + 5  # String + int without conversion
data = [1, 2, 3]
data.append().get("key")  # Mixed list/dict operations

# Wrong API usage
response = requests.get("http://example.com", method="POST")  # Wrong parameter

# Datetime confusion
current_time = datetime.now() + 30  # Missing timedelta
"#;
    
    let temp_dir = TempDir::new().unwrap();
    let suspicious_file = temp_dir.path().join("suspicious.py");
    fs::write(&suspicious_file, suspicious_code).unwrap();
    
    let result = analyze_file(&suspicious_file).unwrap();
    
    assert_eq!(result.file_type, FileType::Python);
    
    // Should detect suspicious patterns
    let has_impossible_params = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "impossible_params"));
    let has_contradictory_names = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "contradictory_names"));
    let has_type_errors = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "string_plus_int"));
    let has_wrong_api = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r == "wrong_api_usage"));
    
    assert!(has_impossible_params, "Should detect suspicious function parameters");
    assert!(has_contradictory_names, "Should detect contradictory function names");
    assert!(has_type_errors, "Should detect type errors");
    assert!(has_wrong_api, "Should detect wrong API usage");
    
    // Trust score should be low due to suspicious patterns
    assert!(result.trust_score < 60, "Suspicious code should have low trust score, got {}", result.trust_score);
}

#[test]
fn test_cargo_test_execution() {
    // This test verifies that we can run the test suite successfully
    // It's more of a meta-test to ensure our test infrastructure works
    assert!(true, "If this test runs, cargo test is working");
}