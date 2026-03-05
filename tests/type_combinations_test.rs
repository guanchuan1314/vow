use std::path::PathBuf;
use vow::analyzers::type_combinations::TypeCombinationAnalyzer;
use vow::{FileType, Severity};

#[cfg(test)]
mod type_combination_tests {
    use super::*;

    #[test]
    fn test_typescript_string_method_on_number() {
        let content = r#"
let count: number = 5;
console.log(count.split(','));
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.ts"), content);
        
        assert_eq!(result.file_type, FileType::TypeScript);
        assert!(result.issues.len() > 0);
        
        let has_string_method_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") && 
            issue.message.contains("number") &&
            issue.severity == Severity::High
        });
        assert!(has_string_method_issue, "Should detect string method on number type");
    }

    #[test]
    fn test_javascript_number_assignment_string_method() {
        let content = r#"
let x = 42;
console.log(x.charAt(0));
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") && 
            issue.message.contains("assigned a number")
        });
        assert!(has_issue, "Should detect string method on number-assigned variable");
    }

    #[test]
    fn test_javascript_array_method_on_object() {
        let content = r#"
let obj = {name: "test", value: 42};
obj.push("new item");
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("array method") && 
            issue.message.contains("object literal")
        });
        assert!(has_issue, "Should detect array method on object literal");
    }

    #[test]
    fn test_javascript_string_arithmetic() {
        let content = r#"
let result = "hello" * 5;
let other = 10 + "world";
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() >= 1); // Should detect at least one arithmetic issue
        
        let has_string_arithmetic = result.issues.iter().any(|issue| {
            issue.message.contains("Arithmetic operation") && 
            issue.message.contains("string") &&
            issue.message.contains("number")
        });
        assert!(has_string_arithmetic, "Should detect string arithmetic operations");
    }

    #[test]
    fn test_javascript_boolean_arithmetic() {
        let content = r#"
let result = true + 5;
let other = 10 * false;
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() >= 1);
        
        let has_boolean_arithmetic = result.issues.iter().any(|issue| {
            issue.message.contains("Boolean used in arithmetic context")
        });
        assert!(has_boolean_arithmetic, "Should detect boolean arithmetic operations");
    }

    #[test]
    fn test_javascript_null_method_call() {
        let content = r#"
let data = null;
console.log(data.toString());
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() > 0);
        
        let has_null_method = result.issues.iter().any(|issue| {
            issue.message.contains("Method call on variable assigned null")
        });
        assert!(has_null_method, "Should detect method call on null");
    }

    #[test]
    fn test_typescript_type_assertion_contradiction() {
        let content = r#"
let data = someValue as string;
let result = data + 42;
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.ts"), content);
        
        assert_eq!(result.file_type, FileType::TypeScript);
        assert!(result.issues.len() > 0);
        
        let has_contradiction = result.issues.iter().any(|issue| {
            issue.message.contains("asserted as string") &&
            issue.message.contains("arithmetic")
        });
        assert!(has_contradiction, "Should detect type assertion contradiction");
    }

    #[test]
    fn test_python_string_method_on_number_typed() {
        let content = r#"
count: int = 5
result = count.split(',')
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") &&
            issue.message.contains("int")
        });
        assert!(has_issue, "Should detect string method on int-typed variable");
    }

    #[test]
    fn test_python_number_assignment_string_method() {
        let content = r#"
x = 42
result = x.upper()
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") &&
            issue.message.contains("assigned a number")
        });
        assert!(has_issue, "Should detect string method on number-assigned variable");
    }

    #[test]
    fn test_python_list_method_on_dict() {
        let content = r#"
data = {"key": "value", "num": 42}
data.append("new_item")
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("list method") &&
            issue.message.contains("dictionary")
        });
        assert!(has_issue, "Should detect list method on dictionary");
    }

    #[test]
    fn test_python_dict_method_on_list() {
        let content = r#"
items = [1, 2, 3, "test"]
value = items.get("key")
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("dict method") &&
            issue.message.contains("list")
        });
        assert!(has_issue, "Should detect dict method on list");
    }

    #[test]
    fn test_python_string_plus_int() {
        let content = r#"
result = "hello" + 42
other = 10 + "world"
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() >= 1);
        
        let has_string_concat_error = result.issues.iter().any(|issue| {
            issue.message.contains("String concatenation with number") &&
            issue.message.contains("TypeError")
        });
        assert!(has_string_concat_error, "Should detect string + int TypeError");
    }

    #[test]
    fn test_python_none_method_call() {
        let content = r#"
data = None
result = data.strip()
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        let has_none_method = result.issues.iter().any(|issue| {
            issue.message.contains("Method call on variable assigned None")
        });
        assert!(has_none_method, "Should detect method call on None");
    }

    #[test]
    fn test_rust_string_method_on_number() {
        let content = r#"
let count: i32 = 5;
let parts = count.split(',');
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.rs"), content);
        
        assert_eq!(result.file_type, FileType::Rust);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") &&
            issue.message.contains("numeric type") &&
            issue.severity == Severity::Critical
        });
        assert!(has_issue, "Should detect string method on numeric type");
    }

    #[test]
    fn test_rust_vec_method_on_scalar() {
        let content = r#"
let value: i32 = 42;
value.push(10);
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.rs"), content);
        
        assert_eq!(result.file_type, FileType::Rust);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("Vec method") &&
            issue.message.contains("scalar type") &&
            issue.severity == Severity::Critical
        });
        assert!(has_issue, "Should detect Vec method on scalar type");
    }

    #[test]
    fn test_rust_option_unwrap_on_non_option() {
        let content = r#"
let value: String = "test".to_string();
let result = value.unwrap();
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.rs"), content);
        
        assert_eq!(result.file_type, FileType::Rust);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("Option method") &&
            issue.message.contains("non-Option type") &&
            issue.severity == Severity::Critical
        });
        assert!(has_issue, "Should detect Option method on non-Option type");
    }

    #[test]
    fn test_rust_string_arithmetic() {
        let content = r#"
let result = "hello" + 5;
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.rs"), content);
        
        assert_eq!(result.file_type, FileType::Rust);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("Arithmetic operation") &&
            issue.message.contains("invalid in Rust") &&
            issue.severity == Severity::Critical
        });
        assert!(has_issue, "Should detect invalid string arithmetic in Rust");
    }

    #[test]
    fn test_generic_null_method_call() {
        let content = r#"
let result = null.toString();
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("Method call on null") &&
            issue.severity == Severity::High
        });
        assert!(has_issue, "Should detect method call on null literal");
    }

    #[test]
    fn test_javascript_array_constructor_confusion() {
        let content = r#"
let arr = new Array(5);
let parts = arr.split(',');
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.js"), content);
        
        assert_eq!(result.file_type, FileType::JavaScript);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") &&
            issue.message.contains("Array constructor")
        });
        assert!(has_issue, "Should detect string method on Array constructor");
    }

    #[test]
    fn test_python_string_format_on_number() {
        let content = r#"
x = 42
result = x.format("test")
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.py"), content);
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("format") &&
            issue.message.contains("numbers don't have format method")
        });
        assert!(has_issue, "Should detect .format() on number");
    }

    #[test]
    fn test_context_aware_analysis() {
        let content = r#"
let count: number = 5;
let name: string = "test";
// This should trigger context-aware detection
count.charAt(0);  // Wrong: string method on number
name.push("x");   // Wrong: array method on string
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.ts"), content);
        
        assert_eq!(result.file_type, FileType::TypeScript);
        assert!(result.issues.len() >= 2, "Should detect both issues in context-aware analysis");
        
        let has_string_on_number = result.issues.iter().any(|issue| {
            issue.message.contains("Calling string method") &&
            issue.message.contains("'count' of type 'number'")
        });
        let has_array_on_string = result.issues.iter().any(|issue| {
            issue.message.contains("Calling array method") &&
            issue.message.contains("'name' of type 'string'")
        });
        
        assert!(has_string_on_number, "Should detect string method on number in context");
        assert!(has_array_on_string, "Should detect array method on string in context");
    }

    #[test]
    fn test_valid_code_no_false_positives() {
        let content = r#"
// Valid TypeScript code
let count: number = 5;
let name: string = "test";
let items: number[] = [1, 2, 3];

// These are all valid operations
let doubled = count * 2;
let upper = name.toUpperCase();
let first = items[0];
items.push(4);
let parts = name.split(',');
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.ts"), content);
        
        assert_eq!(result.file_type, FileType::TypeScript);
        // Should have few or no issues for valid code
        let type_issues = result.issues.iter().filter(|issue| {
            issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination"))
        }).count();
        assert!(type_issues == 0, "Should not flag valid code operations");
    }

    #[test]
    fn test_complex_multiline_analysis() {
        let content = r#"
function processData() {
    let count: number = 5;
    
    // Some other code in between
    console.log("Processing...");
    let intermediate = count + 10;
    
    // The problematic line should still be detected
    let result = count.split(',');
    return result;
}
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.ts"), content);
        
        assert_eq!(result.file_type, FileType::TypeScript);
        assert!(result.issues.len() > 0);
        
        let has_issue = result.issues.iter().any(|issue| {
            issue.message.contains("string method") &&
            issue.line.is_some() &&
            issue.line.unwrap() > 5  // Should be detected on later line
        });
        assert!(has_issue, "Should detect issues across multiple lines");
    }

    #[test]
    fn test_unsupported_file_type_no_analysis() {
        let content = r#"
# This is a plain text file
Some random content that looks like code:
let x = 5;
x.split(',');
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.txt"), content);
        
        // Text files are not analyzed by type combination analyzer
        let type_issues = result.issues.iter().filter(|issue| {
            issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination"))
        }).count();
        assert_eq!(type_issues, 0, "Should not analyze unsupported file types");
    }

    #[test]
    fn test_trust_score_calculation() {
        let content = r#"
let count: number = 5;
count.split(',');  // High severity
count.charAt(0);   // High severity
"#;
        let analyzer = TypeCombinationAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.ts"), content);
        
        assert_eq!(result.file_type, FileType::TypeScript);
        assert!(result.issues.len() >= 2);
        
        // With multiple high severity issues, trust score should be significantly reduced
        assert!(result.trust_score < 80, "Trust score should be reduced with multiple type issues");
    }
}