use std::path::Path;
use vow::{analyze_content, ProjectResults, AnalysisResult, ProjectSummary};
use vow::report::html;
use std::collections::HashMap;

#[test]
fn test_html_report_generation() {
    // Create test data
    let test_content = r#"
password = "hardcoded123"
api_key = "secret123"
"#;
    
    let path = Path::new("test.py");
    let result = analyze_content(path, test_content).expect("Failed to analyze content");
    
    // Create project results
    let mut issues_by_severity = HashMap::new();
    for issue in &result.issues {
        let severity_str = format!("{:?}", issue.severity).to_lowercase();
        *issues_by_severity.entry(severity_str).or_insert(0) += 1;
    }
    
    let project_results = ProjectResults {
        files: vec![result],
        summary: ProjectSummary {
            total_files: 1,
            avg_score: 75,
            total_issues: issues_by_severity.values().sum(),
            issues_by_severity,
            files_per_second: 10.0,
            total_time_seconds: 0.1,
            files_skipped: 0,
            skipped_reasons: HashMap::new(),
        },
    };
    
    // Generate HTML report
    let html_output = html::generate_html_report(&project_results)
        .expect("Failed to generate HTML report");
    
    // Verify HTML structure
    assert!(html_output.contains("<!DOCTYPE html>"));
    assert!(html_output.contains("<title>Vow Analysis Report</title>"));
    assert!(html_output.contains("Vow Analysis Report"));
    assert!(html_output.contains("Files Analyzed"));
    assert!(html_output.contains("Trust Score"));
    assert!(html_output.contains("Total Issues"));
    assert!(html_output.contains("test.py"));
    
    // Verify theme toggle functionality
    assert!(html_output.contains("toggleTheme()"));
    assert!(html_output.contains("data-theme"));
    
    // Verify collapsible file sections
    assert!(html_output.contains("toggleFile"));
    assert!(html_output.contains("file-content"));
    
    // Check for responsive design
    assert!(html_output.contains("@media (max-width: 768px)"));
    
    // Verify inline CSS is present (self-contained)
    assert!(html_output.contains("<style>"));
    assert!(html_output.contains("--bg-color"));
    assert!(html_output.contains("--text-color"));
}

#[test]
fn test_html_report_empty_results() {
    let project_results = ProjectResults {
        files: vec![],
        summary: ProjectSummary {
            total_files: 0,
            avg_score: 100,
            total_issues: 0,
            issues_by_severity: HashMap::new(),
            files_per_second: 0.0,
            total_time_seconds: 0.0,
            files_skipped: 0,
            skipped_reasons: HashMap::new(),
        },
    };
    
    let html_output = html::generate_html_report(&project_results)
        .expect("Failed to generate HTML report for empty results");
    
    // Should still contain basic structure
    assert!(html_output.contains("<!DOCTYPE html>"));
    assert!(html_output.contains("Files Analyzed"));
    assert!(html_output.contains("<div class=\"value\">0</div>"));
    assert!(html_output.contains("100%"));
}

#[test]
fn test_html_print_report() {
    // Create simple test data
    let project_results = ProjectResults {
        files: vec![],
        summary: ProjectSummary {
            total_files: 1,
            avg_score: 85,
            total_issues: 0,
            issues_by_severity: HashMap::new(),
            files_per_second: 5.0,
            total_time_seconds: 0.2,
            files_skipped: 0,
            skipped_reasons: HashMap::new(),
        },
    };
    
    // This should not panic
    let result = html::print_html_report(&project_results);
    assert!(result.is_ok(), "HTML report printing should not fail");
}