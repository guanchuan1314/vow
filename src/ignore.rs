use std::collections::HashMap;
use std::path::Path;
use crate::{Issue, FileType};

/// Represents an ignore directive found in source code
#[derive(Debug, Clone)]
pub struct IgnoreDirective {
    /// Line number where the directive appears
    pub line: usize,
    /// Type of ignore directive
    pub directive_type: IgnoreType,
    /// Optional rule name to ignore (None means ignore all)
    pub rule_name: Option<String>,
}

/// Types of ignore directives
#[derive(Debug, Clone, PartialEq)]
pub enum IgnoreType {
    /// Ignore issues on the current line
    SameLine,
    /// Ignore issues on the line before the directive
    PreviousLine,
    /// Ignore issues on the next line after the directive
    NextLine,
}

/// Parse ignore directives from source content
pub fn parse_ignore_directives(content: &str, file_type: FileType) -> Vec<IgnoreDirective> {
    let mut directives = Vec::new();
    let comment_prefixes = get_comment_prefixes(file_type);

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        for prefix in &comment_prefixes {
            // Check for various ignore patterns
            if let Some(ignore_directive) = parse_ignore_line(trimmed, prefix, line_num) {
                directives.push(ignore_directive);
                break; // Found a directive on this line, no need to check other prefixes
            }
        }
    }

    directives
}

/// Get comment prefixes for different file types
fn get_comment_prefixes(file_type: FileType) -> Vec<&'static str> {
    match file_type {
        FileType::Python | FileType::Shell | FileType::YAML | FileType::R => vec!["#"],
        FileType::JavaScript | FileType::TypeScript | FileType::Rust | FileType::Java 
        | FileType::Go | FileType::C | FileType::Cpp | FileType::CSharp | FileType::PHP 
        | FileType::Swift | FileType::Kotlin | FileType::MQL5 | FileType::Scala 
        | FileType::Dart => vec!["//"],
        FileType::CSS => vec!["/*", "//"], // CSS supports both
        FileType::HTML => vec!["<!--"],
        FileType::Lua => vec!["--"],
        FileType::Haskell => vec!["--"],
        FileType::Perl => vec!["#"],
        // For other/unknown file types, try common patterns
        _ => vec!["//", "#"],
    }
}

/// Parse a single line for ignore directives
fn parse_ignore_line(line: &str, comment_prefix: &str, line_num: usize) -> Option<IgnoreDirective> {
    if !line.contains(comment_prefix) {
        return None;
    }

    // Find the comment part
    let comment_start = line.find(comment_prefix)?;
    let comment_part = &line[comment_start + comment_prefix.len()..].trim();

    // Check for different ignore patterns
    if let Some(directive) = parse_vow_ignore(comment_part, line_num) {
        return Some(directive);
    }

    if let Some(directive) = parse_vow_ignore_next_line(comment_part, line_num) {
        return Some(directive);
    }

    None
}

/// Parse "vow-ignore" or "vow-ignore:rule-name" patterns
fn parse_vow_ignore(comment: &str, line_num: usize) -> Option<IgnoreDirective> {
    // Look for vow-ignore pattern
    if let Some(vow_ignore_start) = comment.find("vow-ignore") {
        let after_ignore = &comment[vow_ignore_start + "vow-ignore".len()..];
        
        // Check if it's vow-ignore:rule-name
        if after_ignore.starts_with(':') {
            let rule_part = &after_ignore[1..].trim();
            // Extract rule name (everything until whitespace or end)
            let rule_name = rule_part.split_whitespace().next().unwrap_or("");
            if !rule_name.is_empty() {
                return Some(IgnoreDirective {
                    line: line_num,
                    directive_type: IgnoreType::SameLine,
                    rule_name: Some(rule_name.to_string()),
                });
            }
        } else if after_ignore.is_empty() || after_ignore.chars().next().map_or(true, |c| c.is_whitespace()) {
            // Plain vow-ignore (ignore all rules)
            return Some(IgnoreDirective {
                line: line_num,
                directive_type: IgnoreType::SameLine,
                rule_name: None,
            });
        }
    }

    None
}

/// Parse "vow-ignore-next-line" or "vow-ignore-next-line:rule-name" patterns
fn parse_vow_ignore_next_line(comment: &str, line_num: usize) -> Option<IgnoreDirective> {
    if let Some(ignore_start) = comment.find("vow-ignore-next-line") {
        let after_ignore = &comment[ignore_start + "vow-ignore-next-line".len()..];
        
        // Check if it's vow-ignore-next-line:rule-name
        if after_ignore.starts_with(':') {
            let rule_part = &after_ignore[1..].trim();
            let rule_name = rule_part.split_whitespace().next().unwrap_or("");
            if !rule_name.is_empty() {
                return Some(IgnoreDirective {
                    line: line_num,
                    directive_type: IgnoreType::NextLine,
                    rule_name: Some(rule_name.to_string()),
                });
            }
        } else if after_ignore.is_empty() || after_ignore.chars().next().map_or(true, |c| c.is_whitespace()) {
            // Plain vow-ignore-next-line
            return Some(IgnoreDirective {
                line: line_num,
                directive_type: IgnoreType::NextLine,
                rule_name: None,
            });
        }
    }

    None
}

/// Filter issues based on ignore directives
pub fn filter_ignored_issues(
    issues: Vec<Issue>,
    directives: &[IgnoreDirective],
    strict_mode: bool,
) -> (Vec<Issue>, usize) {
    if strict_mode || directives.is_empty() {
        return (issues, 0);
    }

    // Create a map of line number to directives for faster lookup
    let mut directive_map: HashMap<usize, Vec<&IgnoreDirective>> = HashMap::new();
    for directive in directives {
        directive_map.entry(directive.line).or_default().push(directive);
    }

    let mut filtered_issues = Vec::new();
    let mut suppressed_count = 0;

    for issue in issues {
        if let Some(issue_line) = issue.line {
            let mut should_ignore = false;

            // Check for same-line ignores
            if let Some(line_directives) = directive_map.get(&issue_line) {
                for directive in line_directives {
                    if directive.directive_type == IgnoreType::SameLine {
                        if should_ignore_issue(&issue, directive) {
                            should_ignore = true;
                            break;
                        }
                    }
                }
            }

            // Check for previous-line ignores (vow-ignore on the line before)
            if !should_ignore && issue_line > 1 {
                if let Some(prev_line_directives) = directive_map.get(&(issue_line - 1)) {
                    for directive in prev_line_directives {
                        if directive.directive_type == IgnoreType::SameLine {
                            if should_ignore_issue(&issue, directive) {
                                should_ignore = true;
                                break;
                            }
                        }
                    }
                }
            }

            // Check for next-line ignores (vow-ignore-next-line on the line before)
            if !should_ignore && issue_line > 1 {
                if let Some(prev_line_directives) = directive_map.get(&(issue_line - 1)) {
                    for directive in prev_line_directives {
                        if directive.directive_type == IgnoreType::NextLine {
                            if should_ignore_issue(&issue, directive) {
                                should_ignore = true;
                                break;
                            }
                        }
                    }
                }
            }

            if should_ignore {
                suppressed_count += 1;
            } else {
                filtered_issues.push(issue);
            }
        } else {
            // Issues without line numbers cannot be ignored
            filtered_issues.push(issue);
        }
    }

    (filtered_issues, suppressed_count)
}

/// Check if an issue should be ignored based on a directive
fn should_ignore_issue(issue: &Issue, directive: &IgnoreDirective) -> bool {
    match &directive.rule_name {
        Some(rule_name) => {
            // Specific rule ignore - check if issue rule matches
            issue.rule.as_ref().map_or(false, |issue_rule| issue_rule == rule_name)
        }
        None => {
            // General ignore - ignore all issues
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Severity, FileType};

    #[test]
    fn test_parse_python_ignore_directives() {
        let content = r#"
import os
# vow-ignore
eval("test")
# vow-ignore:dangerous_function
exec("bad code")  
# vow-ignore-next-line  
eval("another test")
# vow-ignore-next-line:hardcoded_secret
API_KEY = "secret123"
"#;

        let directives = parse_ignore_directives(content, FileType::Python);
        assert_eq!(directives.len(), 4);

        // Check first directive (vow-ignore)
        assert_eq!(directives[0].line, 3);
        assert_eq!(directives[0].directive_type, IgnoreType::SameLine);
        assert_eq!(directives[0].rule_name, None);

        // Check second directive (vow-ignore:dangerous_function)
        assert_eq!(directives[1].line, 5);
        assert_eq!(directives[1].directive_type, IgnoreType::SameLine);
        assert_eq!(directives[1].rule_name, Some("dangerous_function".to_string()));

        // Check third directive (vow-ignore-next-line)
        assert_eq!(directives[2].line, 7);
        assert_eq!(directives[2].directive_type, IgnoreType::NextLine);
        assert_eq!(directives[2].rule_name, None);

        // Check fourth directive (vow-ignore-next-line:hardcoded_secret)
        assert_eq!(directives[3].line, 9);
        assert_eq!(directives[3].directive_type, IgnoreType::NextLine);
        assert_eq!(directives[3].rule_name, Some("hardcoded_secret".to_string()));
    }

    #[test]
    fn test_parse_javascript_ignore_directives() {
        let content = r#"
const fs = require('fs');
// vow-ignore
eval('dangerous code');
// vow-ignore:security_issue
process.env.API_KEY = "hardcoded";
"#;

        let directives = parse_ignore_directives(content, FileType::JavaScript);
        assert_eq!(directives.len(), 2);

        assert_eq!(directives[0].line, 3);
        assert_eq!(directives[0].directive_type, IgnoreType::SameLine);
        assert_eq!(directives[0].rule_name, None);

        assert_eq!(directives[1].line, 5);
        assert_eq!(directives[1].directive_type, IgnoreType::SameLine);
        assert_eq!(directives[1].rule_name, Some("security_issue".to_string()));
    }

    #[test]
    fn test_filter_ignored_issues() {
        let issues = vec![
            Issue {
                severity: Severity::High,
                message: "Dangerous eval usage".to_string(),
                line: Some(4),
                rule: Some("dangerous_function".to_string()),
                suggestion: None,
            },
            Issue {
                severity: Severity::Medium,
                message: "Hardcoded secret".to_string(),
                line: Some(6),
                rule: Some("hardcoded_secret".to_string()),
                suggestion: None,
            },
            Issue {
                severity: Severity::Low,
                message: "Code smell".to_string(),
                line: Some(8),
                rule: Some("code_smell".to_string()),
                suggestion: None,
            },
        ];

        let directives = vec![
            IgnoreDirective {
                line: 4,
                directive_type: IgnoreType::SameLine,
                rule_name: Some("dangerous_function".to_string()),
            },
            IgnoreDirective {
                line: 5,
                directive_type: IgnoreType::NextLine,
                rule_name: None,
            },
        ];

        let (filtered, suppressed) = filter_ignored_issues(issues, &directives, false);
        
        assert_eq!(filtered.len(), 1); // Only the code_smell issue should remain
        assert_eq!(suppressed, 2); // Two issues should be suppressed
        assert_eq!(filtered[0].rule, Some("code_smell".to_string()));
    }

    #[test]
    fn test_strict_mode_ignores_directives() {
        let issues = vec![
            Issue {
                severity: Severity::High,
                message: "Dangerous eval usage".to_string(),
                line: Some(4),
                rule: Some("dangerous_function".to_string()),
                suggestion: None,
            },
        ];

        let directives = vec![
            IgnoreDirective {
                line: 4,
                directive_type: IgnoreType::SameLine,
                rule_name: None,
            },
        ];

        let (filtered, suppressed) = filter_ignored_issues(issues, &directives, true);
        
        assert_eq!(filtered.len(), 1); // Issue should not be suppressed in strict mode
        assert_eq!(suppressed, 0); // No issues suppressed in strict mode
    }

    #[test]
    fn test_issues_without_line_numbers() {
        let issues = vec![
            Issue {
                severity: Severity::High,
                message: "File-level issue".to_string(),
                line: None,
                rule: Some("file_level".to_string()),
                suggestion: None,
            },
        ];

        let directives = vec![
            IgnoreDirective {
                line: 1,
                directive_type: IgnoreType::SameLine,
                rule_name: None,
            },
        ];

        let (filtered, suppressed) = filter_ignored_issues(issues, &directives, false);
        
        assert_eq!(filtered.len(), 1); // Issues without line numbers cannot be ignored
        assert_eq!(suppressed, 0);
    }

    #[test]
    fn test_comment_prefix_detection() {
        assert_eq!(get_comment_prefixes(FileType::Python), vec!["#"]);
        assert_eq!(get_comment_prefixes(FileType::JavaScript), vec!["//"]);
        assert_eq!(get_comment_prefixes(FileType::Rust), vec!["//"]);
        assert_eq!(get_comment_prefixes(FileType::Shell), vec!["#"]);
        assert!(get_comment_prefixes(FileType::CSS).contains(&"/*"));
        assert_eq!(get_comment_prefixes(FileType::HTML), vec!["<!--"]);
    }

    #[test]
    fn test_ignore_inline_comments() {
        let content = r#"
eval("test")  # vow-ignore
dangerous_call()  // vow-ignore:security_issue  
"#;

        let directives = parse_ignore_directives(content, FileType::Python);
        assert_eq!(directives.len(), 2);
        
        assert_eq!(directives[0].line, 2);
        assert_eq!(directives[0].rule_name, None);
        
        assert_eq!(directives[1].line, 3);
        assert_eq!(directives[1].rule_name, Some("security_issue".to_string()));
    }

    #[test]
    fn test_previous_line_ignore() {
        let issues = vec![
            Issue {
                severity: Severity::High,
                message: "Dangerous function".to_string(),
                line: Some(5),
                rule: Some("dangerous_function".to_string()),
                suggestion: None,
            },
        ];

        let directives = vec![
            IgnoreDirective {
                line: 4, // Previous line
                directive_type: IgnoreType::SameLine,
                rule_name: Some("dangerous_function".to_string()),
            },
        ];

        let (filtered, suppressed) = filter_ignored_issues(issues, &directives, false);
        
        assert_eq!(filtered.len(), 0); // Issue should be suppressed
        assert_eq!(suppressed, 1);
    }

    #[test]
    fn test_next_line_ignore() {
        let issues = vec![
            Issue {
                severity: Severity::High,
                message: "Dangerous function".to_string(),
                line: Some(5),
                rule: Some("dangerous_function".to_string()),
                suggestion: None,
            },
        ];

        let directives = vec![
            IgnoreDirective {
                line: 4, // Previous line with next-line directive
                directive_type: IgnoreType::NextLine,
                rule_name: None,
            },
        ];

        let (filtered, suppressed) = filter_ignored_issues(issues, &directives, false);
        
        assert_eq!(filtered.len(), 0); // Issue should be suppressed
        assert_eq!(suppressed, 1);
    }
}