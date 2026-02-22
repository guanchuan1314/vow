pub mod analyzers;
pub mod rules;
pub mod report;

use std::path::PathBuf;

/// Main verification function
pub fn check_path(
    path: PathBuf, 
    format: String, 
    rules: Option<PathBuf>
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking path: {:?}", path);
    
    // Analyze the path
    let analysis_result = analyze_path(&path)?;
    
    // Apply rules
    let rule_results = apply_rules(&analysis_result, rules)?;
    
    // Generate report
    generate_report(&rule_results, &format)?;
    
    Ok(())
}

/// Analyze a path using available analyzers
fn analyze_path(path: &PathBuf) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    // For now, return a dummy analysis result
    Ok(AnalysisResult {
        path: path.clone(),
        file_type: detect_file_type(path),
        issues: vec![],
    })
}

/// Apply rules to analysis results
fn apply_rules(
    _analysis: &AnalysisResult, 
    _rules: Option<PathBuf>
) -> Result<RuleResults, Box<dyn std::error::Error>> {
    // For now, return a dummy rule result
    Ok(RuleResults {
        trust_score: 85,
        checks: vec![
            CheckResult { name: "Syntax Check".to_string(), passed: true },
            CheckResult { name: "Security Scan".to_string(), passed: true },
            CheckResult { name: "API Validation".to_string(), passed: false },
        ],
    })
}

/// Generate report in the specified format
fn generate_report(
    results: &RuleResults, 
    format: &str
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "terminal" => report::terminal::print_terminal_report(results),
        "json" => report::json::print_json_report(results)?,
        _ => return Err("Unsupported format".into()),
    }
    
    Ok(())
}

/// Detect file type from path
fn detect_file_type(path: &PathBuf) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension {
            "py" => FileType::Python,
            "js" | "ts" => FileType::JavaScript,
            "rs" => FileType::Rust,
            "md" => FileType::Markdown,
            _ => FileType::Text,
        }
    } else {
        FileType::Unknown
    }
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub file_type: FileType,
    pub issues: Vec<Issue>,
}

#[derive(Debug)]
pub struct Issue {
    pub severity: Severity,
    pub message: String,
    pub line: Option<usize>,
}

#[derive(Debug)]
pub enum FileType {
    Python,
    JavaScript,
    Rust,
    Markdown,
    Text,
    Unknown,
}

#[derive(Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct RuleResults {
    pub trust_score: u8,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
}