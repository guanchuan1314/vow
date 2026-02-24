use crate::ProjectResults;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Serialize, Deserialize)]
pub struct SummaryReport {
    pub files_checked: usize,
    pub files_passed: usize,
    pub files_failed: usize,
    pub total_issues: usize,
}

/// Print results in summary format (compact one-line-per-file)
pub fn print_summary_report(results: &ProjectResults) {
    let mut passed = 0;
    let mut failed = 0;

    // Print each file result
    for file_result in &results.files {
        if file_result.issues.is_empty() {
            println!("✓ {}", file_result.path.display());
            passed += 1;
        } else {
            println!("✗ {} ({} issues)", 
                file_result.path.display(), 
                file_result.issues.len());
            failed += 1;
        }
    }

    // Print totals
    println!("{} files checked, {} passed, {} failed, {} total issues",
        results.summary.total_files,
        passed,
        failed,
        results.summary.total_issues
    );
}

/// Print results in JSON summary format
pub fn print_json_summary_report(results: &ProjectResults) -> Result<(), Box<dyn std::error::Error>> {
    let passed = results.files.iter()
        .filter(|file| file.issues.is_empty())
        .count();
    let failed = results.files.len() - passed;

    let summary = SummaryReport {
        files_checked: results.summary.total_files,
        files_passed: passed,
        files_failed: failed,
        total_issues: results.summary.total_issues,
    };

    let json_output = serde_json::to_string_pretty(&summary)?;
    println!("{}", json_output);
    Ok(())
}