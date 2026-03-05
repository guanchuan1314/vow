use crate::{ProjectResults, Severity};
use serde::{Deserialize, Serialize};
use serde_json;

/// SARIF 2.1.0 format structures
#[derive(Serialize, Deserialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize, Deserialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize, Deserialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize, Deserialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize, Deserialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfiguration,
    #[serde(rename = "helpUri")]
    help_uri: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SarifConfiguration {
    level: String,
}

#[derive(Serialize, Deserialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize, Deserialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize, Deserialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize, Deserialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize, Deserialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startColumn")]
    start_column: Option<u32>,
}

/// Print results in SARIF format for GitHub/GitLab integration
pub fn print_sarif_report(results: &ProjectResults) -> Result<(), Box<dyn std::error::Error>> {
    // Collect unique rules from all issues
    let mut unique_rules: std::collections::HashMap<String, (String, Severity)> = std::collections::HashMap::new();
    
    for file_result in &results.files {
        for issue in &file_result.issues {
            if let Some(ref rule_name) = issue.rule {
                unique_rules.insert(
                    rule_name.clone(),
                    (issue.message.clone(), issue.severity.clone())
                );
            }
        }
    }
    
    // Convert to SARIF rules
    let mut sarif_rules = Vec::new();
    let mut rule_index_map = std::collections::HashMap::new();
    
    for (index, (rule_id, (message, severity))) in unique_rules.iter().enumerate() {
        let vow_rule_id = convert_to_vow_rule_id(rule_id);
        rule_index_map.insert(rule_id.clone(), index);
        
        sarif_rules.push(SarifRule {
            id: vow_rule_id.clone(),
            name: vow_rule_id.clone(),
            short_description: SarifMessage {
                text: message.clone(),
            },
            full_description: SarifMessage {
                text: format!("Vow detected: {}", message),
            },
            default_configuration: SarifConfiguration {
                level: severity_to_sarif_level(severity),
            },
            help_uri: Some("https://getvow.dev/rules".to_string()),
        });
    }
    
    // Convert results
    let mut sarif_results = Vec::new();
    
    for file_result in &results.files {
        for issue in &file_result.issues {
            let internal_rule_id = issue.rule.as_ref().unwrap_or(&"unknown".to_string()).clone();
            let vow_rule_id = convert_to_vow_rule_id(&internal_rule_id);
            let rule_index = *rule_index_map.get(&internal_rule_id).unwrap_or(&0);
            
            sarif_results.push(SarifResult {
                rule_id: vow_rule_id,
                rule_index,
                level: severity_to_sarif_level(&issue.severity),
                message: SarifMessage {
                    text: issue.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: file_result.path.to_string_lossy().to_string(),
                            uri_base_id: None,
                        },
                        region: SarifRegion {
                            start_line: issue.line.unwrap_or(1) as u32,
                            start_column: Some(1),
                        },
                    },
                }],
            });
        }
    }
    
    let sarif_report = SarifReport {
        schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Vow".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: "https://getvow.dev".to_string(),
                    rules: sarif_rules,
                },
            },
            results: sarif_results,
        }],
    };
    
    let json_output = serde_json::to_string_pretty(&sarif_report)?;
    println!("{}", json_output);
    Ok(())
}

fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low => "note".to_string(),
    }
}

/// Convert internal rule names to VOW-prefixed rule IDs for SARIF compliance
fn convert_to_vow_rule_id(rule_name: &str) -> String {
    match rule_name {
        "hallucinated_api" => "VOW001-hallucinated-import".to_string(),
        "eval_usage" => "VOW002-injection-risk".to_string(),
        "system_calls" => "VOW003-system-calls".to_string(),
        "api_keys" => "VOW004-hardcoded-secrets".to_string(),
        "hardcoded_secrets" => "VOW005-hardcoded-credentials".to_string(),
        "hardcoded_passwords" => "VOW006-hardcoded-passwords".to_string(),
        "dangerous_deserialize" => "VOW007-unsafe-deserialization".to_string(),
        "process_injection" => "VOW008-process-injection".to_string(),
        "reverse_shell" => "VOW009-reverse-shell".to_string(),
        "base64_instructions" => "VOW010-encoded-payload".to_string(),
        "secret_file_access" => "VOW011-sensitive-file-access".to_string(),
        "ai_identity" => "VOW012-ai-generated-text".to_string(),
        "ai_language" => "VOW013-ai-language-patterns".to_string(),
        "formal_transitions" => "VOW014-ai-formal-language".to_string(),
        "unsourced_claims" => "VOW015-unsourced-claims".to_string(),
        "max_issues_limit" => "VOW999-analysis-limit".to_string(),
        _ => format!("VOW-{}", rule_name), // Fallback for any unknown rules
    }
}