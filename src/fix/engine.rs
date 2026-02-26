use std::path::Path;
use std::fs;
use std::collections::HashMap;
use crate::{Issue, AnalysisResult};
use regex::Regex;

/// Represents a fix suggestion with line information
#[derive(Debug, Clone)]
pub struct FixSuggestion {
    pub line: Option<usize>,
    pub original_text: String,
    pub replacement_text: String,
    pub description: String,
}

/// Apply auto-fix suggestions to files
pub fn apply_fixes(results: &mut [AnalysisResult], verbose: bool) -> Result<usize, Box<dyn std::error::Error>> {
    let mut files_fixed = 0;
    let mut total_fixes = 0;

    for result in results.iter_mut() {
        let fixes: Vec<FixSuggestion> = result.issues.iter()
            .filter_map(|issue| create_fix_from_issue(issue))
            .collect();

        if !fixes.is_empty() {
            match apply_fixes_to_file(&result.path, &fixes, verbose) {
                Ok(applied_count) => {
                    if applied_count > 0 {
                        files_fixed += 1;
                        total_fixes += applied_count;
                        
                        if verbose {
                            println!("✅ Applied {} fixes to {}", applied_count, result.path.display());
                        }
                        
                        // Remove fixed issues from the result
                        result.issues.retain(|issue| {
                            !issue.suggestion.as_ref().is_some_and(|s| !s.is_empty())
                        });
                    }
                },
                Err(e) => {
                    if verbose {
                        eprintln!("❌ Failed to apply fixes to {}: {}", result.path.display(), e);
                    }
                }
            }
        }
    }

    if files_fixed > 0 {
        println!("🔧 Applied {} fixes across {} files", total_fixes, files_fixed);
    } else {
        println!("ℹ️ No fixes available to apply");
    }

    Ok(files_fixed)
}

/// Create a fix suggestion from an issue
fn create_fix_from_issue(issue: &Issue) -> Option<FixSuggestion> {
    if let Some(suggestion) = &issue.suggestion {
        if let Some(line) = issue.line {
            // Try to parse the suggestion for common fix patterns
            if let Some(fix) = parse_fix_suggestion(suggestion, &issue.message) {
                return Some(FixSuggestion {
                    line: Some(line),
                    original_text: String::new(), // Will be filled when reading the file
                    replacement_text: fix,
                    description: format!("Fix for: {}", issue.message),
                });
            }
        }
    }
    None
}

/// Parse fix suggestion text to extract the actual fix
pub fn parse_fix_suggestion(suggestion: &str, _message: &str) -> Option<String> {
    // Handle different fix patterns
    
    // Remove line pattern
    if suggestion.starts_with("REMOVE_LINE") {
        return Some(String::new()); // Empty string means remove the line
    }
    
    // Replace pattern: REPLACE: old_text -> new_text
    if let Some(replace_match) = Regex::new(r"REPLACE:\s*(.+?)\s*->\s*(.+)")
        .ok()?
        .captures(suggestion) 
    {
        return Some(replace_match[2].to_string());
    }
    
    // Wrap in try-catch pattern
    if suggestion.starts_with("WRAP_TRY_CATCH") {
        return Some(suggestion.replacen("WRAP_TRY_CATCH:", "", 1));
    }
    
    // Direct replacement
    if suggestion.starts_with("REPLACE_WITH:") {
        return Some(suggestion.replacen("REPLACE_WITH:", "", 1).trim().to_string());
    }
    
    // Default: treat the whole suggestion as replacement text
    Some(suggestion.to_string())
}

/// Apply fixes to a specific file
fn apply_fixes_to_file(
    file_path: &Path,
    fixes: &[FixSuggestion],
    verbose: bool
) -> Result<usize, Box<dyn std::error::Error>> {
    if fixes.is_empty() {
        return Ok(0);
    }

    // Read the file content
    let content = fs::read_to_string(file_path)?;
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut applied_fixes = 0;

    // Group fixes by line number for efficient processing
    let mut fixes_by_line: HashMap<usize, Vec<&FixSuggestion>> = HashMap::new();
    for fix in fixes {
        if let Some(line_num) = fix.line {
            fixes_by_line.entry(line_num).or_default().push(fix);
        }
    }

    // Apply fixes in reverse order to maintain line numbers
    let mut line_numbers: Vec<_> = fixes_by_line.keys().copied().collect();
    line_numbers.sort_unstable();
    line_numbers.reverse();

    for line_num in line_numbers {
        if let Some(line_fixes) = fixes_by_line.get(&line_num) {
            let line_index = line_num.saturating_sub(1);
            if line_index < lines.len() {
                for fix in line_fixes {
                    if fix.replacement_text.is_empty() {
                        // Remove the line
                        lines.remove(line_index);
                        applied_fixes += 1;
                        if verbose {
                            println!("  🗑️ Removed line {}", line_num);
                        }
                    } else {
                        // Replace or modify the line
                        let original_line = &lines[line_index];
                        
                        // Apply the fix based on the pattern
                        let new_line = apply_line_fix(original_line, fix);
                        
                        if new_line != *original_line {
                            lines[line_index] = new_line;
                            applied_fixes += 1;
                            if verbose {
                                println!("  🔄 Modified line {}: {}", line_num, fix.description);
                            }
                        }
                    }
                }
            }
        }
    }

    if applied_fixes > 0 {
        // Write the modified content back to the file
        let new_content = lines.join("\n");
        fs::write(file_path, new_content)?;
    }

    Ok(applied_fixes)
}

/// Apply a fix to a specific line
fn apply_line_fix(original_line: &str, fix: &FixSuggestion) -> String {
    // If it's a wrap pattern, wrap the line
    if fix.replacement_text.contains("{ORIGINAL}") {
        return fix.replacement_text.replace("{ORIGINAL}", original_line);
    }
    
    // Direct replacement
    fix.replacement_text.clone()
}

/// Show fix suggestions without applying them
pub fn show_suggestions(results: &[AnalysisResult]) {
    let mut total_suggestions = 0;
    
    for result in results {
        let suggestions: Vec<_> = result.issues.iter()
            .filter(|issue| issue.suggestion.is_some())
            .collect();
            
        if !suggestions.is_empty() {
            println!("\n📁 {}", result.path.display());
            
            for issue in suggestions {
                if let Some(suggestion) = &issue.suggestion {
                    total_suggestions += 1;
                    
                    let severity_icon = match issue.severity {
                        crate::Severity::Critical => "🔴",
                        crate::Severity::High => "🟠",
                        crate::Severity::Medium => "🟡",
                        crate::Severity::Low => "🔵",
                    };
                    
                    if let Some(line) = issue.line {
                        println!("  {} Line {}: {}", severity_icon, line, issue.message);
                    } else {
                        println!("  {} {}", severity_icon, issue.message);
                    }
                    
                    println!("    💡 Suggestion: {}", suggestion);
                }
            }
        }
    }
    
    if total_suggestions == 0 {
        println!("ℹ️ No fix suggestions available");
    } else {
        println!("\n💡 Found {} fix suggestions. Use --fix to apply them.", total_suggestions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Issue, Severity, AnalysisResult, FileType};
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_parse_fix_suggestion() {
        assert_eq!(
            parse_fix_suggestion("REMOVE_LINE", ""),
            Some(String::new())
        );
        
        assert_eq!(
            parse_fix_suggestion("REPLACE: old_code -> new_code", ""),
            Some("new_code".to_string())
        );
        
        assert_eq!(
            parse_fix_suggestion("REPLACE_WITH: import os", ""),
            Some("import os".to_string())
        );
    }

    #[test]
    fn test_create_fix_from_issue() {
        let issue = Issue {
            severity: Severity::Medium,
            message: "Test issue".to_string(),
            line: Some(5),
            rule: Some("test_rule".to_string()),
            suggestion: Some("REPLACE_WITH: fixed_code".to_string()),
        };
        
        let fix = create_fix_from_issue(&issue);
        assert!(fix.is_some());
        
        let fix = fix.unwrap();
        assert_eq!(fix.line, Some(5));
        assert_eq!(fix.replacement_text, "fixed_code");
    }

    #[test]
    fn test_show_suggestions() {
        let issue = Issue {
            severity: Severity::High,
            message: "Hallucinated import".to_string(),
            line: Some(1),
            rule: Some("hallucinated_import".to_string()),
            suggestion: Some("REMOVE_LINE".to_string()),
        };
        
        let result = AnalysisResult {
            path: PathBuf::from("test.py"),
            file_type: FileType::Python,
            issues: vec![issue],
            trust_score: 75,
        };
        
        // This test mainly checks that show_suggestions doesn't panic
        show_suggestions(&[result]);
    }
}