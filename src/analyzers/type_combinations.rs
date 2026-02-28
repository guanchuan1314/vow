use std::path::Path;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;
use once_cell::sync::Lazy;

/// Type combination detection patterns for different languages
static TYPE_COMBINATION_PATTERNS: Lazy<Vec<TypeCombinationPattern>> = Lazy::new(|| vec![
    // Simple patterns that don't require backreferences - more complex logic handled in context analysis
    TypeCombinationPattern {
        name: "js_string_arithmetic",
        regex: Regex::new(r#""[^"]*"\s*[\+\-\*/]\s*\d+|\d+\s*[\+\-\*/]\s*"[^"]*""#).unwrap(),
        message: "Arithmetic operation between string literal and number (may produce NaN)",
        severity: Severity::Medium,
        file_types: vec![FileType::JavaScript, FileType::TypeScript],
    },
    TypeCombinationPattern {
        name: "js_boolean_arithmetic",
        regex: Regex::new(r"(?:true|false)\s*[\+\-\*/]\s*\d+|\d+\s*[\+\-\*/]\s*(?:true|false)").unwrap(),
        message: "Boolean used in arithmetic context (implicit conversion)",
        severity: Severity::Medium,
        file_types: vec![FileType::JavaScript, FileType::TypeScript],
    },
    TypeCombinationPattern {
        name: "py_string_plus_int",
        regex: Regex::new(r#""[^"]*"\s*\+\s*\d+|\d+\s*\+\s*"[^"]*""#).unwrap(),
        message: "String concatenation with number without conversion (TypeError)",
        severity: Severity::High,
        file_types: vec![FileType::Python],
    },
    TypeCombinationPattern {
        name: "rust_string_arithmetic",
        regex: Regex::new(r#""[^"]*"\s*[\+\-\*/]\s*\d+|\d+\s*[\+\-\*/]\s*"[^"]*""#).unwrap(),
        message: "Arithmetic operation between string and number (invalid in Rust)",
        severity: Severity::Critical,
        file_types: vec![FileType::Rust],
    },

    // Generic patterns that apply to multiple languages
    TypeCombinationPattern {
        name: "generic_null_undefined_method_call",
        regex: Regex::new(r"(?:null|undefined|None|nil)\s*\.\s*\w+\s*\(").unwrap(),
        message: "Method call on null/undefined/None value",
        severity: Severity::High,
        file_types: vec![FileType::JavaScript, FileType::TypeScript, FileType::Python, FileType::Ruby, FileType::Swift],
    },

    // More sophisticated patterns
    TypeCombinationPattern {
        name: "js_array_constructor_confusion",
        regex: Regex::new(r"new Array\(\d+\)\s*\.\s*(split|replace|charAt|indexOf|slice|substring)").unwrap(),
        message: "Calling string method on Array constructor result",
        severity: Severity::High,
        file_types: vec![FileType::JavaScript, FileType::TypeScript],
    },
]);

/// Pattern for detecting impossible type combinations
struct TypeCombinationPattern {
    name: &'static str,
    regex: Regex,
    message: &'static str,
    severity: Severity,
    file_types: Vec<FileType>,
}

/// Analyzer for detecting impossible type combinations in code
pub struct TypeCombinationAnalyzer {
    patterns: &'static [TypeCombinationPattern],
}

impl TypeCombinationAnalyzer {
    pub fn new() -> Self {
        TypeCombinationAnalyzer {
            patterns: &TYPE_COMBINATION_PATTERNS,
        }
    }

    /// Analyze content for impossible type combinations
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = crate::detect_file_type(path);
        let mut issues = Vec::new();

        for pattern in self.patterns {
            // Only apply patterns that match the file type
            if !pattern.file_types.contains(&file_type) {
                continue;
            }

            for captures in pattern.regex.captures_iter(content) {
                let line_number = content[..captures.get(0).unwrap().start()]
                    .lines()
                    .count();

                issues.push(Issue {
                    severity: pattern.severity.clone(),
                    message: format!("{} (pattern: {})", pattern.message, pattern.name),
                    line: Some(line_number),
                    rule: Some(format!("type_combination_{}", pattern.name)),
                    suggestion: None,
                });
            }
        }

        // Additional context-aware analysis for more complex cases
        if matches!(file_type, FileType::TypeScript | FileType::JavaScript) {
            self.analyze_js_ts_context(content, &mut issues);
        }

        if matches!(file_type, FileType::Python) {
            self.analyze_python_context(content, &mut issues);
        }

        if matches!(file_type, FileType::Rust) {
            self.analyze_rust_context(content, &mut issues);
        }

        let trust_score = self.calculate_trust_score(&issues);

        AnalysisResult {
            path: path.to_path_buf(),
            file_type,
            issues,
            trust_score,
        }
    }

    /// Context-aware analysis for JavaScript/TypeScript
    fn analyze_js_ts_context(&self, content: &str, issues: &mut Vec<Issue>) {
        // Look for variables declared with specific types and later misused
        let lines: Vec<&str> = content.lines().collect();
        let mut variable_types: std::collections::HashMap<String, (String, usize)> = std::collections::HashMap::new();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let line = line.trim();

            // Track variable declarations with type annotations
            if let Some(captures) = Regex::new(r"(?:let|const|var)\s+(\w+)\s*:\s*(string|number|boolean|object|\w+\[\])\s*=").unwrap().captures(line) {
                let var_name = captures.get(1).unwrap().as_str().to_string();
                let var_type = captures.get(2).unwrap().as_str().to_string();
                variable_types.insert(var_name, (var_type, line_num));
            }

            // Track variable assignments to infer types
            if let Some(captures) = Regex::new(r#"(?:let|const|var)\s+(\w+)\s*=\s*(\d+|"[^"]*"|'[^']*'|\[.*\]|\{.*\}|true|false|null|undefined)"#).unwrap().captures(line) {
                let var_name = captures.get(1).unwrap().as_str().to_string();
                let value = captures.get(2).unwrap().as_str();
                let inferred_type = if value.parse::<i64>().is_ok() {
                    "number".to_string()
                } else if value.starts_with('"') || value.starts_with('\'') {
                    "string".to_string()
                } else if value.starts_with('[') {
                    "array".to_string()
                } else if value.starts_with('{') {
                    "object".to_string()
                } else if value == "true" || value == "false" {
                    "boolean".to_string()
                } else if value == "null" || value == "undefined" {
                    "null".to_string()
                } else {
                    "unknown".to_string()
                };
                variable_types.insert(var_name, (inferred_type, line_num));
            }

            // Check for method calls on tracked variables
            for (var_name, (var_type, _decl_line)) in &variable_types {
                if line.contains(&format!("{}.", var_name)) {
                    self.check_method_type_compatibility(var_name, var_type, line, line_num, issues);
                }
            }
        }
    }

    /// Context-aware analysis for Python
    fn analyze_python_context(&self, content: &str, issues: &mut Vec<Issue>) {
        let lines: Vec<&str> = content.lines().collect();
        let mut variable_types: std::collections::HashMap<String, (String, usize)> = std::collections::HashMap::new();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let line = line.trim();

            // Skip comments
            if line.starts_with('#') {
                continue;
            }

            // Track variable type annotations
            if let Some(captures) = Regex::new(r"(\w+)\s*:\s*(int|float|str|bool|list|dict|List\[\w+\]|Dict\[\w+,\s*\w+\])\s*=").unwrap().captures(line) {
                let var_name = captures.get(1).unwrap().as_str().to_string();
                let var_type = captures.get(2).unwrap().as_str().to_string();
                variable_types.insert(var_name, (var_type, line_num));
            }

            // Track variable assignments to infer types
            if let Some(captures) = Regex::new(r#"(\w+)\s*=\s*(\d+|"[^"]*"|'[^']*'|\[.*\]|\{.*\}|True|False|None)"#).unwrap().captures(line) {
                let var_name = captures.get(1).unwrap().as_str().to_string();
                let value = captures.get(2).unwrap().as_str();
                let inferred_type = if value.parse::<i64>().is_ok() {
                    "int".to_string()
                } else if value.parse::<f64>().is_ok() {
                    "float".to_string()
                } else if value.starts_with('"') || value.starts_with('\'') {
                    "str".to_string()
                } else if value.starts_with('[') {
                    "list".to_string()
                } else if value.starts_with('{') {
                    "dict".to_string()
                } else if value == "True" || value == "False" {
                    "bool".to_string()
                } else if value == "None" {
                    "None".to_string()
                } else {
                    "unknown".to_string()
                };
                variable_types.insert(var_name, (inferred_type, line_num));
            }

            // Check for method calls on tracked variables
            for (var_name, (var_type, _decl_line)) in &variable_types {
                if line.contains(&format!("{}.", var_name)) {
                    self.check_python_method_type_compatibility(var_name, var_type, line, line_num, issues);
                }
            }
        }
    }

    /// Context-aware analysis for Rust
    fn analyze_rust_context(&self, content: &str, issues: &mut Vec<Issue>) {
        let lines: Vec<&str> = content.lines().collect();
        let mut variable_types: std::collections::HashMap<String, (String, usize)> = std::collections::HashMap::new();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let line = line.trim();

            // Skip comments
            if line.starts_with("//") {
                continue;
            }

            // Track let bindings with explicit types
            if let Some(captures) = Regex::new(r"let\s+(\w+)\s*:\s*(i32|i64|u32|u64|f32|f64|usize|isize|bool|String|&str|Vec<\w+>|Option<\w+>|Result<\w+,\s*\w+>)\s*=").unwrap().captures(line) {
                let var_name = captures.get(1).unwrap().as_str().to_string();
                let var_type = captures.get(2).unwrap().as_str().to_string();
                variable_types.insert(var_name, (var_type, line_num));
            }

            // Track let bindings with inferred types from literals
            if let Some(captures) = Regex::new(r#"let\s+(\w+)\s*=\s*(\d+|"[^"]*"|true|false|\[.*\]|vec!\[.*\]|Some\(.*\)|None|Ok\(.*\)|Err\(.*\))"#).unwrap().captures(line) {
                let var_name = captures.get(1).unwrap().as_str().to_string();
                let value = captures.get(2).unwrap().as_str();
                let inferred_type = if value.parse::<i64>().is_ok() {
                    if value.contains('.') { "f64".to_string() } else { "i32".to_string() }
                } else if value.starts_with('"') {
                    "String".to_string()
                } else if value == "true" || value == "false" {
                    "bool".to_string()
                } else if value.starts_with("vec!") || value.starts_with('[') {
                    "Vec<T>".to_string()
                } else if value.starts_with("Some(") || value == "None" {
                    "Option<T>".to_string()
                } else if value.starts_with("Ok(") || value.starts_with("Err(") {
                    "Result<T,E>".to_string()
                } else {
                    "unknown".to_string()
                };
                variable_types.insert(var_name, (inferred_type, line_num));
            }

            // Check for method calls on tracked variables
            for (var_name, (var_type, _decl_line)) in &variable_types {
                if line.contains(&format!("{}.", var_name)) {
                    self.check_rust_method_type_compatibility(var_name, var_type, line, line_num, issues);
                }
            }
        }
    }

    /// Check method compatibility for JavaScript/TypeScript
    fn check_method_type_compatibility(&self, var_name: &str, var_type: &str, line: &str, line_num: usize, issues: &mut Vec<Issue>) {
        let string_methods = ["split", "replace", "indexOf", "slice", "substring", "charAt", "toLowerCase", "toUpperCase", "trim"];
        let array_methods = ["push", "pop", "shift", "unshift", "splice", "concat", "join", "indexOf", "includes", "find", "filter", "map"];
        let number_methods = ["toFixed", "toPrecision", "toString", "valueOf"];

        for method in &string_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && var_type != "string" && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::High,
                    message: format!("Calling string method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }

        for method in &array_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && !var_type.contains("[]") && var_type != "array" && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::High,
                    message: format!("Calling array method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }

        for method in &number_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && var_type != "number" && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::High,
                    message: format!("Calling number method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }
    }

    /// Check method compatibility for Python
    fn check_python_method_type_compatibility(&self, var_name: &str, var_type: &str, line: &str, line_num: usize, issues: &mut Vec<Issue>) {
        let string_methods = ["split", "replace", "find", "index", "strip", "lower", "upper", "title", "capitalize", "startswith", "endswith", "join"];
        let list_methods = ["append", "extend", "insert", "remove", "pop", "index", "count", "sort", "reverse"];
        let dict_methods = ["get", "keys", "values", "items", "update", "pop", "clear"];

        for method in &string_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && var_type != "str" && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::High,
                    message: format!("Calling string method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }

        for method in &list_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && var_type != "list" && !var_type.starts_with("List[") && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::High,
                    message: format!("Calling list method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }

        for method in &dict_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && var_type != "dict" && !var_type.starts_with("Dict[") && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::High,
                    message: format!("Calling dict method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }
    }

    /// Check method compatibility for Rust
    fn check_rust_method_type_compatibility(&self, var_name: &str, var_type: &str, line: &str, line_num: usize, issues: &mut Vec<Issue>) {
        let string_methods = ["split", "replace", "chars", "lines", "trim", "to_lowercase", "to_uppercase", "starts_with", "ends_with", "contains", "find"];
        let vec_methods = ["push", "pop", "len", "is_empty", "insert", "remove", "clear", "append", "extend"];
        let option_methods = ["unwrap", "unwrap_or", "unwrap_or_else", "expect", "is_some", "is_none"];

        for method in &string_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && var_type != "String" && var_type != "&str" && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::Critical,
                    message: format!("Calling string method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }

        for method in &vec_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && !var_type.starts_with("Vec<") && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::Critical,
                    message: format!("Calling Vec method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }

        for method in &option_methods {
            if line.contains(&format!("{}.{}", var_name, method)) && !var_type.starts_with("Option<") && var_type != "unknown" {
                issues.push(Issue {
                    severity: Severity::Critical,
                    message: format!("Calling Option method '{}' on variable '{}' of type '{}'", method, var_name, var_type),
                    line: Some(line_num),
                    rule: Some("type_combination_method_mismatch".to_string()),
                    suggestion: None,
                });
            }
        }
    }

    /// Calculate trust score based on issues
    fn calculate_trust_score(&self, issues: &[Issue]) -> u8 {
        let mut score = 100u8;
        for issue in issues {
            score = score.saturating_sub(match issue.severity {
                Severity::Critical => 30,
                Severity::High => 20,
                Severity::Medium => 10,
                Severity::Low => 5,
            });
        }
        score
    }
}

impl Default for TypeCombinationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
