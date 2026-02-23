use std::path::PathBuf;
use vow::analyzers::code::CodeAnalyzer;

#[test]
fn test_yaml_config_hardcoded_secrets() {
    // Issue #3: YAML/config files hardcoded secrets
    let yaml_content = r#"
database:
  host: localhost
  password: "supersecretpassword123"
  api_key: "sk-1234567890abcdef"
  
redis:
  host: localhost  
  secret: very_long_secret_key_12345
  token: "access_token_abcdefghij"

app:
  aws_secret: AKIAIOSFODNN7EXAMPLE
  private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKBwko="
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("config.yaml"), yaml_content);
    
    // Should detect hardcoded secrets
    assert!(result.issues.len() > 0);
    
    let secret_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "yaml_config_secrets"))
        .collect();
    
    assert!(secret_issues.len() > 0, "Should detect hardcoded secrets in YAML");
}

#[test] 
fn test_env_file_hardcoded_secrets() {
    // Issue #3: .env files hardcoded secrets
    let env_content = r#"
# Database configuration
DATABASE_PASSWORD=supersecret123
API_KEY=sk-1234567890abcdef
ACCESS_TOKEN=ghp_1234567890abcdef

# AWS configuration  
AWS_SECRET=AKIAIOSFODNN7EXAMPLE
PRIVATE_KEY=very_long_private_key_12345

# Safe values (should not trigger)
DATABASE_HOST=localhost
PORT=3306
DEBUG=true
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from(".env"), env_content);
    
    let secret_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "env_file_secrets"))
        .collect();
    
    assert!(secret_issues.len() > 0, "Should detect hardcoded secrets in .env file");
}

#[test]
fn test_sql_injection_detection() {
    // Issue #4: SQL injection across multiple languages
    
    // Python SQL injection
    let python_content = r#"
cursor.execute("SELECT * FROM users WHERE id = " + str(user_id) + " AND name = '" + username + "'")
query("UPDATE accounts SET balance = " + amount + " WHERE id = " + account_id)

# Safe parameterized query (should not trigger)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.py"), python_content);
    
    let sql_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "sql_injection_python"))
        .collect();
    
    assert!(sql_issues.len() > 0, "Should detect SQL injection in Python");

    // JavaScript SQL injection
    let js_content = r#"
const query = "SELECT * FROM users WHERE id = " + userId + " AND role = '" + userRole + "'";
execute("DELETE FROM sessions WHERE token = " + token + " AND expires < " + timestamp);

// Safe query (should not trigger)
const safeQuery = "SELECT * FROM users WHERE id = ?";
"#;

    let result = analyzer.analyze(&PathBuf::from("test.js"), js_content);
    
    let sql_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "sql_injection_js"))
        .collect();
    
    assert!(sql_issues.len() > 0, "Should detect SQL injection in JavaScript");
}

#[test]
fn test_shell_script_hardcoded_secrets() {
    // Issue #5: Shell script hardcoded secrets
    let shell_content = r#"#!/bin/bash

# Hardcoded secrets (should trigger)
PASSWORD=supersecretpassword123
API_KEY=sk-1234567890abcdef
TOKEN=ghp_abcdef1234567890
AWS_SECRET=AKIAIOSFODNN7EXAMPLE
DB_PASSWORD=database_password_123

# Safe variables (should not trigger)
HOST=localhost
PORT=3306
DEBUG=true
USER=admin
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("setup.sh"), shell_content);
    
    let secret_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "shell_hardcoded_secrets"))
        .collect();
    
    assert!(secret_issues.len() > 0, "Should detect hardcoded secrets in shell script");
}

#[test] 
fn test_remote_script_pipe_detection() {
    // Issue #6: curl|bash and wget|sh patterns
    let shell_content = r#"#!/bin/bash

# Dangerous patterns (should trigger)
curl -sSL https://get.docker.com/ | bash
wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
curl https://sh.rustup.rs | sh
wget https://install.python.org/get-pip.py | python

# Safer patterns (should not trigger as much)
curl -sSL https://get.docker.com/ -o docker-install.sh
wget https://install.python.org/get-pip.py
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("install.sh"), shell_content);
    
    let pipe_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule == "remote_script_pipe" || rule == "curl_bash_oneliner" || rule == "wget_sh_oneliner"
        )).collect();
    
    assert!(pipe_issues.len() > 0, "Should detect dangerous remote script piping");
}

#[test]
fn test_path_traversal_detection() {
    // Issue #7: Path traversal vulnerabilities  
    let content = r#"
// Vulnerable patterns (should trigger)
const content = fs.readFile(userPath + "../../../etc/passwd");
include($basePath . $_GET['file'] . ".php");
open("uploads/" + filename + "/../../../secrets.txt");

// Python examples
with open(base_path + user_input + "/config.txt") as f:
    content = f.read()

file_get_contents($_POST['path'] . "/../admin/config.php");

// Safe patterns (should not trigger) 
const content = fs.readFile(path.join(userDir, sanitize(filename)));
include(SAFE_DIR . "/" . basename($_GET['file']) . ".php");
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.js"), content);
    
    let traversal_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule == "path_traversal_open" || rule == "path_traversal_concatenation"
        )).collect();
    
    assert!(traversal_issues.len() > 0, "Should detect path traversal vulnerabilities");
}

#[test]
fn test_ssrf_detection() {
    // Issue #8: SSRF vulnerabilities
    let content = r#"
// Vulnerable patterns (should trigger)
const response = await fetch("https://api.example.com/" + userUrl + "/data");
axios.get("http://internal.service/" + req.params.endpoint);
requests.get("https://api.service.com/" + user_input + "/info");

// Python examples
urllib.request.urlopen(base_url + user_provided_path);
http.get(host + user_input + "/api/data");

// Safe patterns (should not trigger)
const response = await fetch("https://api.example.com/data");
axios.get(ALLOWED_ENDPOINTS[endpoint_id]);
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.js"), content);
    
    let ssrf_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule == "ssrf_fetch" || rule == "ssrf_url_concat"
        )).collect();
    
    assert!(ssrf_issues.len() > 0, "Should detect SSRF vulnerabilities");
}

#[test]
fn test_open_redirect_detection() {
    // Issue #9: Open redirect vulnerabilities
    let content = r#"
// Vulnerable patterns (should trigger)
res.redirect(req.query.returnUrl + "/dashboard");
window.location = "https://site.com/" + userInput + "/page";
response.sendRedirect(baseUrl + request.getParameter("redirect"));
location.href = "/home" + user_redirect_path;

// Safe patterns (should not trigger)
res.redirect("/dashboard");
window.location = ALLOWED_REDIRECTS[redirect_key];
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.js"), content);
    
    let redirect_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule == "open_redirect" || rule == "location_redirect"
        )).collect();
    
    assert!(redirect_issues.len() > 0, "Should detect open redirect vulnerabilities");
}

#[test]
fn test_ssl_tls_bypass_detection() {
    // Issue #10: SSL/TLS bypass detection
    let content = r#"
// Node.js TLS bypass (should trigger)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
NODE_TLS_REJECT_UNAUTHORIZED=0

// Python SSL bypass (should trigger)
import ssl
context = ssl._create_unverified_context()
requests.get("https://example.com", verify=False)

// Curl SSL bypass (should trigger)
curl -k https://example.com/api
curl --insecure https://self-signed-site.com

// Safe patterns (should not trigger)
requests.get("https://example.com", verify=True)
curl https://example.com/api
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.py"), content);
    
    let ssl_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("ssl") || rule.contains("tls") || rule == "node_tls_reject_disabled"
        )).collect();
    
    assert!(ssl_issues.len() > 0, "Should detect SSL/TLS bypass attempts");
}

#[test]
fn test_prototype_pollution_detection() {
    // Issue #11: Prototype pollution vulnerabilities
    let js_content = r#"
// Vulnerable patterns (should trigger)
Object.assign(target, userInput);
_.merge(config, req.body);
Object.setPrototypeOf(obj, userProto);

// Direct proto assignment (should trigger)
obj["__proto__"] = userInput;
target["constructor"] = maliciousConstructor;
data["prototype"] = userProto;

// Unsafe merge patterns
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];  // No protection against __proto__
    }
}

// Safe patterns (should not trigger)
Object.assign(target, sanitize(userInput));
_.merge(config, _.omit(req.body, ['__proto__', 'constructor']));
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.js"), js_content);
    
    let pollution_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.contains("prototype_pollution") || rule == "proto_assignment"
        )).collect();
    
    assert!(pollution_issues.len() > 0, "Should detect prototype pollution vulnerabilities");
}

#[test]
fn test_java_xxe_detection() {
    // Issue #12: XXE vulnerabilities in Java
    let java_content = r#"
// Vulnerable patterns (should trigger)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
SAXParserFactory spf = SAXParserFactory.newInstance();
XMLReader reader = XMLReaderFactory.createXMLReader();
TransformerFactory tf = TransformerFactory.newInstance();

// These should also trigger
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Transformer transformer = TransformerFactory.newInstance().newTransformer();

// Safe patterns (would require additional secure configuration, not shown here)
// Note: Safe XML parsing requires additional setFeature() calls to disable external entities
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("XMLParser.java"), java_content);
    
    let xxe_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| 
            rule.starts_with("java_xxe_")
        )).collect();
    
    assert!(xxe_issues.len() > 0, "Should detect XXE vulnerabilities in Java");
}

#[test]
fn test_file_type_filtering() {
    // Test that patterns only apply to appropriate file types
    
    // YAML pattern should not trigger on Python file
    let yaml_pattern_in_python = r#"
# This is a Python comment, not YAML
password: "not_really_yaml_supersecret123"
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("test.py"), yaml_pattern_in_python);
    
    let yaml_false_positives: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "yaml_config_secrets"))
        .collect();
    
    assert_eq!(yaml_false_positives.len(), 0, "YAML patterns should not trigger in Python files");

    // Java XXE pattern should not trigger on JavaScript file
    let java_pattern_in_js = r#"
// This is JavaScript, not Java
const factory = DocumentBuilderFactory.newInstance();  // This is just a string/comment
"#;

    let result = analyzer.analyze(&PathBuf::from("test.js"), java_pattern_in_js);
    
    let java_false_positives: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule.starts_with("java_xxe_")))
        .collect();
    
    assert_eq!(java_false_positives.len(), 0, "Java XXE patterns should not trigger in JavaScript files");
}