// Test file for Rust vulnerability detection
use actix_web::{web, HttpResponse, Result};
use reqwest;
use serde::Deserialize;

#[derive(Deserialize)]
struct UserInput {
    pub url: String,
    pub cmd: String,
    pub redirect_url: String,
}

// SSRF vulnerability (#18)
async fn ssrf_vuln(params: web::Query<UserInput>) -> Result<HttpResponse> {
    let response = reqwest::get(&params.url).await.unwrap();
    Ok(HttpResponse::Ok().json("ok"))
}

// Command injection / Eval injection (#22)
async fn eval_injection(params: web::Query<UserInput>) -> Result<HttpResponse> {
    use std::process::Command;
    let output = Command::new(&params.cmd)
        .arg("test")
        .output()
        .expect("failed to execute process");
    Ok(HttpResponse::Ok().json("ok"))
}

// Open redirect (#20)
async fn open_redirect(params: web::Query<UserInput>) -> Result<HttpResponse> {
    Ok(HttpResponse::Found()
        .header("location", &params.redirect_url)
        .finish())
}

// Mass assignment (#25)
#[derive(Deserialize)]
struct User {
    name: String,
    is_admin: bool,
}

async fn mass_assignment(user: web::Json<User>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json("ok"))
}

// CSRF vulnerable endpoint (#26)
#[actix_web::post("/update")]
async fn csrf_vuln() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json("updated"))
}

// IDOR vulnerability (#27)
async fn idor_vuln(path: web::Path<u32>) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    // Direct database access without authorization check
    let user = sqlx::query!("SELECT * FROM users WHERE id = $1", user_id);
    Ok(HttpResponse::Ok().json("ok"))
}

// Buffer overflow in unsafe code (#28)
unsafe fn buffer_overflow() {
    let mut buffer = [0u8; 10];
    let ptr = buffer.as_mut_ptr();
    *ptr.add(15) = 42; // Out of bounds access
}

// Use after free (#31)
unsafe fn use_after_free() {
    let boxed = Box::new(42);
    let raw_ptr = Box::into_raw(boxed);
    drop(Box::from_raw(raw_ptr)); // Free the memory
    let value = *raw_ptr; // Use after free!
}

// Double free (#32)
unsafe fn double_free() {
    let boxed = Box::new(42);
    let raw_ptr = Box::into_raw(boxed);
    drop(Box::from_raw(raw_ptr)); // First free
    drop(Box::from_raw(raw_ptr)); // Double free!
}

// Uninitialized memory (#35)
unsafe fn uninitialized_memory() {
    use std::mem::MaybeUninit;
    let uninit: MaybeUninit<u32> = MaybeUninit::uninit();
    let value = uninit.assume_init(); // Reading uninitialized memory
}

// Race condition (#29)
static mut GLOBAL_COUNTER: u32 = 0;

unsafe fn race_condition() {
    GLOBAL_COUNTER += 1; // Race condition on global mutable static
}

// Integer overflow (#33)
fn integer_overflow(user_input: u32) {
    let result = user_input.wrapping_add(1000000);
    let unchecked = user_input.unchecked_add(1000000);
}

// Format string vulnerability (#34)
fn format_string_vuln(user_input: &str) {
    println!("{}", user_input); // Could be exploitable if user_input contains format specifiers
    format!("User said: {}", user_input);
}

// Type confusion (#36)
unsafe fn type_confusion() {
    let x: u32 = 42;
    let y: f32 = std::mem::transmute(x); // Type confusion
}

// Side channel attack (#37)
fn timing_attack(password: &str, user_input: &str) {
    if password == user_input { // Vulnerable to timing attacks
        println!("Access granted");
    }
}