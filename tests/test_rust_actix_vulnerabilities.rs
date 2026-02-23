use std::path::PathBuf;
use vow::{analyze_content, FileType, Severity};

/// Test cases for all Rust/Actix vulnerability types that should be detected
/// Corresponds to GitHub issues #14-#37

#[test]
fn test_rust_sql_injection_detection() {
    // Issue #14: SQL injection in Rust
    let rust_content = r#"
use std::format;

pub fn get_user_by_id(id: String) -> String {
    let query = format!("SELECT * FROM users WHERE id = '{}'", id);
    // This is vulnerable to SQL injection
    query
}

pub fn search_users(name: String) -> String {
    let sql = "SELECT * FROM users WHERE name = '".to_string() + &name + "'";
    // String concatenation SQL injection
    sql
}

// Safe parameterized query (should not trigger)
pub fn safe_query(id: i32) -> String {
    "SELECT * FROM users WHERE id = $1".to_string() // Parameterized
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    assert_eq!(result.file_type, FileType::Rust);
    
    println!("Total issues found: {}", result.issues.len());
    for issue in &result.issues {
        println!("Issue: {:?} - {}", issue.rule, issue.message);
    }
    
    let sql_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("sql_injection") && rule.contains("rust")))
        .collect();
    
    assert!(sql_issues.len() > 0, "Should detect SQL injection in Rust format! macro");
}

#[test] 
fn test_rust_xss_detection() {
    // Issue #15: XSS in Rust/Actix
    let rust_content = r#"
use actix_web::{HttpResponse, Result};

pub async fn render_user_profile(user_data: String) -> Result<HttpResponse> {
    let html = format!("<h1>Welcome {}</h1><p>Profile: {}</p>", user_data, user_data);
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

pub async fn display_comment(comment: String) -> Result<HttpResponse> {
    let response = "<div>".to_string() + &comment + "</div>";
    Ok(HttpResponse::Ok().body(response))
}

// JavaScript in HTML
pub async fn embed_script(data: String) -> String {
    format!("<script>var data = '{}';</script>", data)
}

// Safe escaped content (should not trigger)
pub async fn safe_html() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().body("<h1>Static Content</h1>"))
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    println!("XSS test - Total issues found: {}", result.issues.len());
    for issue in &result.issues {
        println!("Issue: {:?} - {}", issue.rule, issue.message);
    }
    
    let xss_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("xss") && rule.contains("rust")) || 
            issue.message.contains("XSS"))
        .collect();
    
    assert!(xss_issues.len() > 0, "Should detect XSS vulnerabilities in Rust HTML generation");
}

#[test]
fn test_rust_command_injection_detection() {
    // Issue #16: Command injection in Rust
    let rust_content = r#"
use std::process::Command;

pub fn execute_user_command(user_input: String) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(&user_input)  // Direct user input to shell
        .output()
        .expect("Failed to execute");
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn run_with_format(filename: String) -> std::io::Result<std::process::Output> {
    Command::new("cat").arg(format!("/tmp/{}", filename)).output()
}

// Multiple arguments with user input
pub fn git_operation(branch: String) -> std::io::Result<std::process::Output> {
    Command::new("git").args(&["checkout", &branch]).output()
}

// Safe static command (should not trigger)
pub fn safe_command() -> std::io::Result<std::process::Output> {
    Command::new("ls").arg("/tmp").output()
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    println!("Command injection test - Total issues found: {}", result.issues.len());
    for issue in &result.issues {
        println!("Issue: {:?} - {}", issue.rule, issue.message);
    }
    
    let cmd_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("command") && rule.contains("rust")))
        .collect();
    
    assert!(cmd_issues.len() > 0, "Should detect command injection in Rust Command execution");
}

#[test]
fn test_rust_path_traversal_detection() {
    // Issue #17: Path traversal in Rust
    let rust_content = r#"
use std::fs::File;
use std::path::Path;
use actix_web::{web, HttpResponse, Result};

pub async fn read_user_file(filename: String) -> Result<HttpResponse> {
    let file_path = format!("/uploads/{}", filename);  // Vulnerable to ../
    let contents = std::fs::read_to_string(&file_path);
    Ok(HttpResponse::Ok().body(format!("Contents: {:?}", contents)))
}

pub fn open_file(user_path: String) -> std::io::Result<String> {
    let full_path = "/app/data/".to_string() + &user_path;
    std::fs::read_to_string(full_path)
}

pub async fn serve_file(file: web::Path<String>) -> Result<HttpResponse> {
    let file_path = Path::new("./uploads").join(&*file);  // Still vulnerable
    let contents = std::fs::read_to_string(file_path)?;
    Ok(HttpResponse::Ok().body(contents))
}

// Safe path handling (should not trigger)
pub fn safe_file_access() -> std::io::Result<String> {
    std::fs::read_to_string("/app/config/settings.json")
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    let path_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("path_traversal") && rule.contains("rust")))
        .collect();
    
    assert!(path_issues.len() > 0, "Should detect path traversal vulnerabilities in Rust file operations");
}

#[test]
fn test_rust_ssrf_detection() {
    // Issue #18: SSRF in Rust
    let rust_content = r#"
use reqwest;
use actix_web::{web, HttpResponse, Result};

pub async fn fetch_url(url: String) -> Result<HttpResponse> {
    let response = reqwest::get(&url).await;  // Direct user URL
    match response {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            Ok(HttpResponse::Ok().body(body))
        }
        Err(_) => Ok(HttpResponse::InternalServerError().finish())
    }
}

pub async fn proxy_request(target: web::Path<String>) -> Result<HttpResponse> {
    let client = reqwest::Client::new();
    let url = format!("http://internal-api/{}", target);
    let resp = client.get(&url).send().await?;
    Ok(HttpResponse::Ok().body(resp.text().await?))
}

// Multiple HTTP methods
pub async fn post_to_service(service_url: String, data: String) -> reqwest::Result<reqwest::Response> {
    reqwest::Client::new().post(&service_url).body(data).send().await
}

// Safe SSRF protection (should not trigger)
pub async fn safe_request() -> Result<HttpResponse> {
    let response = reqwest::get("https://api.github.com/users/octocat").await;
    // ... handle response
    Ok(HttpResponse::Ok().finish())
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    let ssrf_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("ssrf") && rule.contains("rust")))
        .collect();
    
    assert!(ssrf_issues.len() > 0, "Should detect SSRF vulnerabilities in Rust HTTP requests");
}

#[test]
fn test_rust_hardcoded_secrets_detection() {
    // Issue #21: Hardcoded secrets in Rust
    let rust_content = r#"
const API_KEY: &str = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DATABASE_PASSWORD: &str = "super_secret_db_password_123";
static JWT_SECRET: &str = "my_jwt_secret_key_do_not_share";

pub struct Config {
    pub api_token: String,
    pub db_connection: String,
}

impl Config {
    pub fn new() -> Self {
        Config {
            api_token: "hardcoded_api_token_12345".to_string(),
            db_connection: "postgresql://user:hardcoded_pass@localhost/db".to_string(),
        }
    }
}

// AWS credentials
const AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Safe configuration (should not trigger)
pub fn get_config() -> Config {
    Config {
        api_token: std::env::var("API_TOKEN").unwrap_or_default(),
        db_connection: std::env::var("DATABASE_URL").unwrap_or_default(),
    }
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    println!("Hardcoded secrets test - Total issues found: {}", result.issues.len());
    for issue in &result.issues {
        println!("Issue: {:?} - {}", issue.rule, issue.message);
    }
    
    let secret_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("hardcoded") || rule.contains("secret") || rule.contains("api_key")))
        .collect();
    
    assert!(secret_issues.len() > 0, "Should detect hardcoded secrets in Rust constants and strings");
}

#[test]
fn test_rust_unsafe_blocks_detection() {
    // Issues #28, #31, #32, #33, #35: Memory safety issues in unsafe blocks
    let rust_content = r#"
pub fn dangerous_unsafe_operations() {
    unsafe {
        // Use after free pattern
        let ptr = Box::into_raw(Box::new(42));
        drop(Box::from_raw(ptr));
        println!("{}", *ptr);  // Use after free
        
        // Double free pattern
        let ptr2 = Box::into_raw(Box::new(100));
        drop(Box::from_raw(ptr2));
        drop(Box::from_raw(ptr2));  // Double free
        
        // Buffer overflow pattern
        let mut buffer = [0u8; 10];
        let ptr = buffer.as_mut_ptr();
        *ptr.offset(20) = 42;  // Buffer overflow
        
        // Uninitialized memory
        let mut uninit: std::mem::MaybeUninit<i32> = std::mem::MaybeUninit::uninit();
        let value = uninit.assume_init();  // Using uninitialized memory
        
        // Integer overflow in unsafe
        let large_num: u8 = 255;
        let overflow = large_num + 1;  // Potential overflow
        
        // Transmute type confusion
        let data: [u8; 4] = [1, 2, 3, 4];
        let int_val: i32 = std::mem::transmute(data);  // Type confusion
    }
}

// Safe Rust code (should not trigger)
pub fn safe_operations() {
    let data = vec![1, 2, 3, 4, 5];
    for item in &data {
        println!("{}", item);
    }
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    let unsafe_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("unsafe") || rule.contains("memory") || rule.contains("rust")))
        .collect();
    
    assert!(unsafe_issues.len() > 0, "Should detect memory safety issues in Rust unsafe blocks");
}

#[test]
fn test_rust_deserialization_detection() {
    // Issue #23: Unsafe deserialization in Rust
    let rust_content = r#"
use serde_json;
use bincode;

pub fn deserialize_user_data(data: String) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(&data)  // Potentially unsafe JSON deserialization
}

pub fn deserialize_binary(data: &[u8]) -> bincode::Result<i32> {
    bincode::deserialize(data)  // Binary deserialization
}

// Pickle-like functionality (very dangerous)
pub fn load_from_bytes(data: Vec<u8>) -> Option<Box<dyn std::any::Any>> {
    // This would be equivalent to pickle.loads() in Python
    // Extremely dangerous deserialization
    None
}

pub fn ron_deserialize(input: &str) -> ron::Result<serde_json::Value> {
    ron::from_str(input)  // RON deserialization
}

// Safe deserialization with validation (should not trigger as much)
pub fn safe_deserialize(data: String) -> Result<serde_json::Value, serde_json::Error> {
    let parsed: serde_json::Value = serde_json::from_str(&data)?;
    // Validate the structure before using
    if parsed.is_object() {
        Ok(parsed)
    } else {
        Err(serde_json::Error::custom("Invalid structure"))
    }
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    let deser_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("deserialization") && rule.contains("rust")))
        .collect();
    
    assert!(deser_issues.len() > 0, "Should detect unsafe deserialization in Rust");
}

#[test]
fn test_rust_actix_csrf_detection() {
    // Issue #26: CSRF vulnerabilities in Actix
    let rust_content = r#"
use actix_web::{web, HttpResponse, Result, HttpRequest};

// Missing CSRF protection
pub async fn delete_user(id: web::Path<u32>) -> Result<HttpResponse> {
    // This endpoint allows state-changing operation without CSRF token
    Ok(HttpResponse::Ok().json("User deleted"))
}

pub async fn transfer_money(
    data: web::Json<TransferRequest>
) -> Result<HttpResponse> {
    // Money transfer without CSRF protection
    Ok(HttpResponse::Ok().json("Transfer completed"))
}

pub async fn change_password(
    req: HttpRequest,
    form: web::Form<PasswordForm>
) -> Result<HttpResponse> {
    // Password change without proper CSRF validation
    Ok(HttpResponse::Ok().json("Password changed"))
}

// Safe CSRF-protected endpoint (should trigger less)
pub async fn protected_action(
    req: HttpRequest,
    form: web::Form<ActionForm>
) -> Result<HttpResponse> {
    if let Some(token) = req.headers().get("x-csrf-token") {
        // Has CSRF token validation
        Ok(HttpResponse::Ok().json("Action completed"))
    } else {
        Ok(HttpResponse::Forbidden().json("Missing CSRF token"))
    }
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    let csrf_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("csrf") && rule.contains("rust")))
        .collect();
    
    assert!(csrf_issues.len() > 0, "Should detect missing CSRF protection in Actix endpoints");
}

#[test]
fn test_rust_concurrency_issues_detection() {
    // Issues #29, #30: Race conditions and concurrency issues
    let rust_content = r#"
use std::sync::{Arc, Mutex};
use std::thread;

static mut GLOBAL_COUNTER: i32 = 0;

pub fn unsafe_global_access() {
    unsafe {
        GLOBAL_COUNTER += 1;  // Race condition on global mutable static
    }
}

pub fn shared_mutable_data() {
    let data = Arc::new(std::cell::RefCell::new(vec![1, 2, 3]));
    let data_clone = Arc::clone(&data);
    
    thread::spawn(move || {
        data_clone.borrow_mut().push(4);  // Potential race condition
    });
    
    data.borrow_mut().push(5);  // Another thread might be modifying
}

// Multiple threads accessing shared data without proper synchronization
pub fn race_condition_example() {
    let counter = Arc::new(std::cell::Cell::new(0));
    let counter_clone = Arc::clone(&counter);
    
    thread::spawn(move || {
        for _ in 0..1000 {
            let val = counter_clone.get();
            counter_clone.set(val + 1);  // Race condition: read-modify-write
        }
    });
    
    for _ in 0..1000 {
        let val = counter.get();
        counter.set(val + 1);  // Race condition: read-modify-write  
    }
}

// Safe concurrency (should not trigger)
pub fn safe_concurrency() {
    let counter = Arc::new(Mutex::new(0));
    let counter_clone = Arc::clone(&counter);
    
    thread::spawn(move || {
        let mut num = counter_clone.lock().unwrap();
        *num += 1;
    });
}
"#;

    let result = analyze_content(&PathBuf::from("test.rs"), rust_content).unwrap();
    
    let race_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("race_condition") || rule.contains("concurrency") && rule.contains("rust")))
        .collect();
    
    assert!(race_issues.len() > 0, "Should detect race conditions and concurrency issues in Rust");
}

#[test]
fn test_all_rust_vulnerabilities_in_one_file() {
    // Combined test with multiple vulnerability types
    let comprehensive_rust_content = r#"
use actix_web::{web, HttpResponse, Result};
use std::process::Command;
use std::fs::File;
use reqwest;

// Hardcoded secrets (#21)
const API_KEY: &str = "sk-1234567890abcdefghijklmnop";
const DB_PASS: &str = "supersecret123";

pub async fn vulnerable_endpoint(
    user_input: web::Path<String>
) -> Result<HttpResponse> {
    // SQL injection (#14) 
    let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
    
    // Command injection (#16)
    let output = Command::new("sh")
        .arg("-c") 
        .arg(&*user_input)
        .output()
        .expect("Command failed");
    
    // XSS (#15)
    let html = format!("<h1>Hello {}</h1>", user_input);
    
    // Path traversal (#17)
    let file_path = format!("/uploads/{}", user_input);
    let contents = std::fs::read_to_string(file_path);
    
    // SSRF (#18) 
    let response = reqwest::get(&format!("http://api.service.com/{}", user_input)).await;
    
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(html))
}

pub unsafe fn memory_issues() {
    // Use after free (#31)
    let ptr = Box::into_raw(Box::new(42));
    drop(Box::from_raw(ptr));
    println!("{}", *ptr);
    
    // Buffer overflow (#28)
    let mut buf = [0u8; 8];  
    let ptr = buf.as_mut_ptr();
    *ptr.offset(20) = 1;
}

// Global mutable state - race condition (#29)
static mut COUNTER: i32 = 0;

pub fn race_condition() {
    unsafe {
        COUNTER += 1;  // Unsafe global access
    }
}
"#;

    let result = analyze_content(&PathBuf::from("comprehensive_vuln.rs"), comprehensive_rust_content).unwrap();
    assert_eq!(result.file_type, FileType::Rust);
    
    // Should detect multiple vulnerability types
    assert!(result.issues.len() > 10, "Should detect many vulnerabilities in comprehensive test");
    
    // Check for specific vulnerability types
    let has_sql_injection = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("sql_injection")));
    let has_xss = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("xss")));
    let has_command_injection = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("command_injection")));
    let has_hardcoded_secrets = result.issues.iter().any(|i| 
        i.rule.as_ref().map_or(false, |r| r.contains("hardcoded_secrets")));
    
    assert!(has_sql_injection, "Should detect SQL injection");
    assert!(has_xss, "Should detect XSS");
    assert!(has_command_injection, "Should detect command injection");
    assert!(has_hardcoded_secrets, "Should detect hardcoded secrets");
    
    // Trust score should be very low due to many vulnerabilities
    assert!(result.trust_score < 30, "Comprehensive vulnerable code should have very low trust score");
}