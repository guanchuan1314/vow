use std::path::PathBuf;
use vow::analyzers::code::CodeAnalyzer;

fn analyze_java(code: &str) -> vow::AnalysisResult {
    let analyzer = CodeAnalyzer::new();
    analyzer.analyze(&PathBuf::from("VulnerableServlet.java"), code)
}

fn has_rule(result: &vow::AnalysisResult, rule_prefix: &str) -> bool {
    result.issues.iter().any(|i| {
        i.rule.as_ref().map_or(false, |r| r.starts_with(rule_prefix))
    })
}

// Group A: Injection Attacks

#[test]
fn test_graphql_injection() {
    let code = r#"String query = "{ query users" + request.getParameter("q") + "}";"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_graphql_injection"),
        "Should detect GraphQL injection. Issues: {:?}", result.issues);
}

#[test]
fn test_nosql_injection() {
    let code = r#"Document doc = Document.parse(request.getParameter("filter"));"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_nosql_injection"),
        "Should detect NoSQL injection. Issues: {:?}", result.issues);
}

#[test]
fn test_nosql_injection_string_concat() {
    let code = "String q = \"{ username: \" + request.getParameter(\"code\") + \" }\";";
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_nosql_injection"),
        "Should detect NoSQL injection string concat. Issues: {:?}", result.issues);
}

#[test]
fn test_second_order_sqli() {
    let code = r#"stmt.executeQuery("SELECT * FROM orders WHERE user = '" + rs.getString("username") + "'");"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_second_order_sqli") || has_rule(&result, "java_servlet_sql_injection"),
        "Should detect second-order SQLi or SQL injection. Issues: {:?}", result.issues);
}

#[test]
fn test_ssti() {
    let code = r#"Velocity.evaluate(context, writer, "log", request.getParameter("template"));"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_ssti"),
        "Should detect SSTI. Issues: {:?}", result.issues);
}

#[test]
fn test_crlf_injection() {
    let code = r#"response.setHeader("X-Custom", request.getParameter("val"));"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_crlf_injection"),
        "Should detect CRLF injection. Issues: {:?}", result.issues);
}

#[test]
fn test_ldap_injection() {
    let code = r#"String filter = "(uid=" + request.getParameter("user") + ")";"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_ldap_injection"),
        "Should detect LDAP injection. Issues: {:?}", result.issues);
}

#[test]
fn test_xml_injection() {
    let code = r#"String xml = "<user>" + request.getParameter("name") + "</user>";"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_xml_injection"),
        "Should detect XML injection. Issues: {:?}", result.issues);
}

// Group B: Access Control / Auth

#[test]
fn test_idor() {
    let code = r#"@PathVariable Long userId"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_idor"),
        "Should detect potential IDOR. Issues: {:?}", result.issues);
}

#[test]
fn test_weak_auth() {
    let code = r#"if (password.equals("admin123")) { grant(); }"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_weak_auth"),
        "Should detect weak authentication. Issues: {:?}", result.issues);
}

// Group C: Memory/Resource Safety

#[test]
fn test_integer_overflow() {
    let code = r#"int id = Integer.parseInt(request.getParameter("id"));"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_integer_overflow"),
        "Should detect integer overflow risk. Issues: {:?}", result.issues);
}

#[test]
fn test_integer_overflow_cast() {
    let code = r#"short val = (short) Long.parseLong(input);"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_integer_overflow"),
        "Should detect narrowing cast. Issues: {:?}", result.issues);
}

#[test]
fn test_resource_leak() {
    let code = r#"FileInputStream fis = new FileInputStream("/tmp/data.txt");"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_resource_leak"),
        "Should detect resource leak. Issues: {:?}", result.issues);
}

#[test]
fn test_null_deref() {
    let code = r#"String name = request.getParameter("name").trim();"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_null_deref"),
        "Should detect null pointer dereference. Issues: {:?}", result.issues);
}

// Group D: Concurrency

#[test]
fn test_race_condition() {
    let code = r#"static int requestCount = 0;"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_race_condition"),
        "Should detect race condition. Issues: {:?}", result.issues);
}

#[test]
fn test_deadlock() {
    let code = r#"synchronized(lockA) { synchronized(lockB) { doStuff(); } }"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_deadlock"),
        "Should detect deadlock risk. Issues: {:?}", result.issues);
}

// Group E: Crypto/Randomness

#[test]
fn test_insecure_random() {
    let code = r#"Random rng = new Random();"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_insecure_random"),
        "Should detect insecure randomness. Issues: {:?}", result.issues);
}

#[test]
fn test_math_random() {
    let code = r#"double token = Math.random();"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_insecure_random"),
        "Should detect Math.random(). Issues: {:?}", result.issues);
}

#[test]
fn test_weak_crypto_des() {
    let code = r#"Cipher c = Cipher.getInstance("DES");"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_weak_crypto"),
        "Should detect weak crypto DES. Issues: {:?}", result.issues);
}

#[test]
fn test_weak_hash_md5() {
    let code = r#"MessageDigest md = MessageDigest.getInstance("MD5");"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_weak_hash"),
        "Should detect weak hash MD5. Issues: {:?}", result.issues);
}

// Group F: File Operations

#[test]
fn test_insecure_file_perms() {
    let code = r#"PosixFilePermissions.fromString("rwxrwxrwx")"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_insecure_file_perms"),
        "Should detect insecure file permissions. Issues: {:?}", result.issues);
}

#[test]
fn test_unrestricted_upload() {
    let code = r#"Part filePart = request.getPart("file");"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_unrestricted_upload"),
        "Should detect unrestricted file upload. Issues: {:?}", result.issues);
}

// Group G: Code Quality / Misc

#[test]
fn test_unsafe_reflection() {
    let code = r#"Class.forName(request.getParameter("class")).newInstance();"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_unsafe_reflection"),
        "Should detect unsafe reflection. Issues: {:?}", result.issues);
}

#[test]
fn test_improper_error_handling_empty_catch() {
    let code = r#"catch (Exception e) {}"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_improper_error_handling"),
        "Should detect empty catch block. Issues: {:?}", result.issues);
}

#[test]
fn test_stacktrace_exposure() {
    let code = r#"e.printStackTrace();"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_stacktrace_exposure"),
        "Should detect stack trace exposure. Issues: {:?}", result.issues);
}

#[test]
fn test_http_smuggling() {
    let code = r#"response.setHeader("Transfer-Encoding", "chunked")"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_http_smuggling"),
        "Should detect HTTP request smuggling risk. Issues: {:?}", result.issues);
}
