use serde::{Deserialize, Serialize};
use crate::RuleResults;

/// SARIF (Static Analysis Results Interchange Format) output
/// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

#[derive(Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub message: SarifMessage,
    pub level: String,
}

#[derive(Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Generate SARIF report (stub implementation)
pub fn generate_sarif_report(results: &RuleResults) -> Result<String, Box<dyn std::error::Error>> {
    let sarif_results: Vec<SarifResult> = results.checks
        .iter()
        .enumerate()
        .filter(|(_, check)| !check.passed)
        .map(|(i, check)| SarifResult {
            rule_id: format!("vow-rule-{}", i),
            message: SarifMessage {
                text: format!("Check failed: {}", check.name),
            },
            level: "error".to_string(),
        })
        .collect();
    
    let report = SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Vow".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: "https://getvow.dev".to_string(),
                },
            },
            results: sarif_results,
        }],
    };
    
    Ok(serde_json::to_string_pretty(&report)?)
}