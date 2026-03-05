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

// #468: SQL Injection
#[test]
fn test_java_servlet_sql_injection() {
    let code = r#"
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_sql_injection") || has_rule(&result, "sql_injection_java"),
        "Should detect SQL injection. Issues: {:?}", result.issues);
}

#[test]
fn test_java_servlet_sql_injection_getparam_concat() {
    let code = r#"
String query = "SELECT * FROM users WHERE name = '" + request.getParameter("name") + "'";
stmt.executeQuery(query);
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_sql_injection"),
        "Should detect SQL injection with getParameter concat. Issues: {:?}", result.issues);
}

// #469: XSS
#[test]
fn test_java_servlet_xss() {
    // XSS: getParameter output directly to getWriter on same line
    let code = r#"
        response.getWriter().println("<h1>" + request.getParameter("name") + "</h1>");
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_xss"),
        "Should detect XSS. Issues: {:?}", result.issues);
}

// #470: Path Traversal
#[test]
fn test_java_servlet_path_traversal() {
    // Path traversal: getParameter directly in File constructor
    let code = r#"
        File f = new File(request.getParameter("path"));
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_path_traversal"),
        "Should detect path traversal. Issues: {:?}", result.issues);
}

#[test]
fn test_java_servlet_path_traversal_direct() {
    let code = r#"
File f = new File(request.getParameter("path"));
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_path_traversal"),
        "Should detect direct path traversal. Issues: {:?}", result.issues);
}

// #471: SSRF
#[test]
fn test_java_servlet_ssrf() {
    let code = r#"
import javax.servlet.http.*;
import java.net.*;

public class ProxyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = request.getParameter("url");
        URL url = new URL(request.getParameter("url")).openConnection();
    }
}
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_ssrf"),
        "Should detect SSRF. Issues: {:?}", result.issues);
}

// #472: Open Redirect
#[test]
fn test_java_servlet_open_redirect() {
    let code = r#"
import javax.servlet.http.*;

public class RedirectServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        response.sendRedirect(request.getParameter("redirect"));
    }
}
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_open_redirect"),
        "Should detect open redirect. Issues: {:?}", result.issues);
}

// #473: Hardcoded Secrets
#[test]
fn test_java_hardcoded_secrets() {
    let code = r#"
public class DatabaseConfig {
    private static final String DB_PASSWORD = "s3cr3tP@ssw0rd!";
    String password = "hardcodedPassword123";
    private static final String API_KEY = "ak_live_1234567890abcdef";
}
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_hardcoded_password") || has_rule(&result, "java_hardcoded_credential") || has_rule(&result, "hardcoded_secrets") || has_rule(&result, "api_keys"),
        "Should detect hardcoded secrets. Issues: {:?}", result.issues);
}

// #474: Insecure Deserialization
#[test]
fn test_java_insecure_deserialization() {
    let code = r#"
import java.io.*;
import javax.servlet.http.*;

public class DeserializeServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();
    }
}
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_insecure_deserialization"),
        "Should detect insecure deserialization. Issues: {:?}", result.issues);
}

// #475: CSRF
#[test]
fn test_java_servlet_csrf() {
    let code = r#"
import javax.servlet.http.*;

public class TransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String amount = request.getParameter("amount");
        String toAccount = request.getParameter("to");
        transferFunds(amount, toAccount);
    }
}
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_csrf"),
        "Should detect CSRF in doPost. Issues: {:?}", result.issues);
}

#[test]
fn test_java_servlet_csrf_post_method_check() {
    let code = r#"
if ("POST".equalsIgnoreCase(request.getMethod())) {
    String data = request.getParameter("data");
    processData(data);
}
"#;
    let result = analyze_java(code);
    assert!(has_rule(&result, "java_servlet_csrf"),
        "Should detect CSRF in POST method check. Issues: {:?}", result.issues);
}
