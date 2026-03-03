use std::path::PathBuf;
use vow::{analyze_content, FileType, Severity};

/// Test cases for Go/net/http vulnerability detection
/// Corresponds to GitHub issues #439-#454

#[test]
fn test_go_sql_injection_sprintf() {
    // Issue #439
    let content = r#"
package main

import (
    "database/sql"
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    rows, _ := db.Query(query)
    defer rows.Close()
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    assert_eq!(result.file_type, FileType::Go);
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("sql_injection")))
        .collect();
    assert!(issues.len() > 0, "Should detect SQL injection via fmt.Sprintf in Go");
}

#[test]
fn test_go_xss_fprintf() {
    // Issue #440
    let content = r#"
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("go_xss")))
        .collect();
    assert!(issues.len() > 0, "Should detect XSS via fmt.Fprintf in Go");
}

#[test]
fn test_go_path_traversal() {
    // Issue #441
    let content = r#"
package main

import (
    "io/ioutil"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    data, _ := ioutil.ReadFile(filename + ".txt")
    w.Write(data)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("path_traversal")))
        .collect();
    assert!(issues.len() > 0, "Should detect path traversal in Go: {:?}", result.issues);
}

#[test]
fn test_go_ssrf() {
    // Issue #442
    let content = r#"
package main

import (
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, _ := http.Get(url)
    defer resp.Body.Close()
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("ssrf")))
        .collect();
    assert!(issues.len() > 0, "Should detect SSRF in Go: {:?}", result.issues);
}

#[test]
fn test_go_xxe() {
    // Issue #443
    let content = r#"
package main

import (
    "encoding/xml"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    var data MyStruct
    xml.Unmarshal(body, &data)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("xxe")))
        .collect();
    assert!(issues.len() > 0, "Should detect XXE in Go");
}

#[test]
fn test_go_open_redirect() {
    // Issue #444
    let content = r#"
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    http.Redirect(w, r, url, http.StatusFound)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("redirect")))
        .collect();
    assert!(issues.len() > 0, "Should detect open redirect in Go: {:?}", result.issues);
}

#[test]
fn test_go_template_injection() {
    // Issue #445
    let content = r#"
package main

import (
    "html/template"
    "net/http"
    "fmt"
)

func handler(w http.ResponseWriter, r *http.Request) {
    userTemplate := r.FormValue("template")
    tmpl := template.Must(template.New("t")).Parse(fmt.Sprintf("<div>%s</div>", userTemplate))
    tmpl.Execute(w, nil)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("template")))
        .collect();
    assert!(issues.len() > 0, "Should detect template injection in Go: {:?}", result.issues);
}

#[test]
fn test_go_idor() {
    // Issue #446
    let content = r#"
package main

import (
    "database/sql"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    db.QueryRow("SELECT * FROM users WHERE id = $1", id)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("idor")))
        .collect();
    assert!(issues.len() > 0, "Should detect IDOR in Go: {:?}", result.issues);
}

#[test]
fn test_go_integer_overflow() {
    // Issue #447
    let content = r#"
package main

import (
    "net/http"
    "strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
    val, _ := strconv.Atoi(r.FormValue("count"))
    result := val * 1024
    _ = result
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("integer_overflow")))
        .collect();
    assert!(issues.len() > 0, "Should detect integer overflow in Go: {:?}", result.issues);
}

#[test]
fn test_go_format_string() {
    // Issue #448
    let content = r#"
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    input := r.FormValue("msg")
    fmt.Fprintf(w, input)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("format_string")))
        .collect();
    assert!(issues.len() > 0, "Should detect format string vuln in Go: {:?}", result.issues);
}

#[test]
fn test_go_weak_crypto() {
    // Issue #449
    let content = r#"
package main

import (
    "crypto/md5"
    "fmt"
)

func hashPassword(password string) string {
    hash := md5.Sum([]byte(password))
    return fmt.Sprintf("%x", hash)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("weak_crypto")))
        .collect();
    assert!(issues.len() > 0, "Should detect weak crypto (MD5) in Go");
}

#[test]
fn test_go_missing_rate_limit() {
    // Issue #450
    let content = r#"
package main

import "net/http"

func main() {
    http.HandleFunc("/api/login", loginHandler)
    http.HandleFunc("/api/transfer", transferHandler)
    http.ListenAndServe(":8080", nil)
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("rate_limit")))
        .collect();
    assert!(issues.len() > 0, "Should detect missing rate limiting in Go");
}

#[test]
fn test_go_missing_csp() {
    // Issue #451
    let content = r#"
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte("<html><body>Hello</body></html>"))
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("csp")))
        .collect();
    assert!(issues.len() > 0, "Should detect missing CSP in Go");
}

#[test]
fn test_go_hardcoded_credentials() {
    // Issue #452
    let content = r#"
package main

var password = "supersecretpassword123"

func authenticate(user, pass string) bool {
    return user == "admin" && pass == password
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("hardcoded") || r.contains("credential") || r.contains("secret")))
        .collect();
    assert!(issues.len() > 0, "Should detect hardcoded credentials in Go: {:?}", result.issues);
}

#[test]
fn test_go_unrestricted_upload() {
    // Issue #453
    let content = r#"
package main

import "net/http"

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("upload")
    defer file.Close()
    _ = header
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("upload")))
        .collect();
    assert!(issues.len() > 0, "Should detect unrestricted file upload in Go");
}

#[test]
fn test_go_ldap_injection() {
    // Issue #454
    let content = r#"
package main

import "fmt"

func searchUser(username string) string {
    filter := fmt.Sprintf("(uid=%s)", username)
    return filter
}
"#;
    let result = analyze_content(&PathBuf::from("test.go"), content).unwrap();
    let issues: Vec<_> = result.issues.iter()
        .filter(|i| i.rule.as_ref().map_or(false, |r| r.contains("ldap")))
        .collect();
    assert!(issues.len() > 0, "Should detect LDAP injection in Go");
}
