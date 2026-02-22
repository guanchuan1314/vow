use crate::ProjectResults;
use serde_json;

/// Print results in JSON format
pub fn print_json_report(results: &ProjectResults) -> Result<(), Box<dyn std::error::Error>> {
    let json_output = serde_json::to_string_pretty(results)?;
    println!("{}", json_output);
    Ok(())
}