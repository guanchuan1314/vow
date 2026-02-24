use std::path::PathBuf;
use std::process::Command;
use std::fs;
use reqwest;

// Hardcoded secrets
const API_KEY: &str = "sk-1234567890abcdefghijklmnop";

pub fn vulnerable_sql(user_input: String) -> String {
    let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
    query
}

pub async fn ssrf_request(url: String) -> Result<String, Box<dyn std::error::Error>> {
    let response = reqwest::get(&url).await?;
    Ok(response.text().await?)
}

pub fn command_injection(input: String) -> std::io::Result<std::process::Output> {
    Command::new("sh").arg("-c").arg(&input).output()
}

pub fn xss_html(user_data: String) -> String {
    format!("<h1>Welcome {}</h1>", user_data)
}