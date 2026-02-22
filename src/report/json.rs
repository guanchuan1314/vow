use serde::{Deserialize, Serialize};
use crate::RuleResults;

#[derive(Serialize, Deserialize)]
pub struct JsonReport {
    pub version: String,
    pub trust_score: u8,
    pub checks: Vec<JsonCheckResult>,
    pub summary: JsonSummary,
}

#[derive(Serialize, Deserialize)]
pub struct JsonCheckResult {
    pub name: String,
    pub passed: bool,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct JsonSummary {
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
}

/// Print results in JSON format
pub fn print_json_report(results: &RuleResults) -> Result<(), Box<dyn std::error::Error>> {
    let passed_checks = results.checks.iter().filter(|c| c.passed).count();
    let failed_checks = results.checks.len() - passed_checks;
    
    let report = JsonReport {
        version: "1.0".to_string(),
        trust_score: results.trust_score,
        checks: results.checks.iter().map(|c| JsonCheckResult {
            name: c.name.clone(),
            passed: c.passed,
            status: if c.passed { "PASS".to_string() } else { "FAIL".to_string() },
        }).collect(),
        summary: JsonSummary {
            total_checks: results.checks.len(),
            passed_checks,
            failed_checks,
        },
    };
    
    println!("{}", serde_json::to_string_pretty(&report)?);
    
    Ok(())
}