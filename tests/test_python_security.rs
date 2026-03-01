use std::path::PathBuf;
use vow::analyzers::code::CodeAnalyzer;

#[test]
fn test_python_sql_injection() {
    // Issue #359, #388: SQL injection vulnerabilities
    let python_content = r#"
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Vulnerable: SQL injection via f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # Vulnerable: SQL injection via string concatenation
    username = request.form.get('username')
    query2 = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query2)
    
    # Vulnerable: SQL injection via % formatting
    email = request.args.get('email')
    query3 = "SELECT * FROM users WHERE email = '%s'" % email
    cursor.execute(query3)
    
    # Safe example (should not trigger)
    query_safe = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query_safe, (user_id,))
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect SQL injection vulnerabilities
    assert!(result.issues.len() > 0);
    
    let sql_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_sql_injection"))
        .collect();
    
    assert!(sql_issues.len() >= 3, "Should detect at least 3 SQL injection patterns");
}

#[test]
fn test_python_xss_ssti() {
    // Issue #360, #365, #387: XSS and SSTI vulnerabilities  
    let python_content = r#"
from flask import Flask, request, render_template_string, Response

app = Flask(__name__)

@app.route('/profile')
def profile():
    username = request.args.get('username')
    
    # Vulnerable: XSS via f-string HTML injection
    html = f"<div>Hello {username}!</div>"
    
    # Vulnerable: SSTI via render_template_string with user input
    template = request.form.get('template')
    rendered = render_template_string(template)
    
    # Vulnerable: Direct HTML response without escaping
    return Response(f"<html><body>Welcome {username}</body></html>")

@app.route('/search')  
def search():
    query = request.args.get('q')
    # Vulnerable: JavaScript injection
    script = f"var searchQuery = '{query}'"
    return Response(f"<script>{script}</script>")
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect XSS/SSTI vulnerabilities
    assert!(result.issues.len() > 0);
    
    let xss_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_xss"))
        .collect();
    
    assert!(xss_issues.len() >= 2, "Should detect XSS and SSTI patterns");
}

#[test]
fn test_python_ssrf() {
    // Issue #362: SSRF vulnerabilities
    let python_content = r#"
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    
    # Vulnerable: SSRF via requests.get with user input
    response = requests.get(url)
    
    # Vulnerable: SSRF via URL construction
    host = request.form.get('host')
    api_url = f"http://{host}/api/data"
    response2 = requests.get(api_url)
    
    # Vulnerable: urllib SSRF
    import urllib.request
    target = request.args.get('target')
    urllib.request.urlopen(target)
    
    return response.text

@app.route('/webhook')
def webhook():
    callback_url = request.json.get('callback_url')
    # Vulnerable: POST to user-controlled URL
    requests.post(callback_url, json={'status': 'success'})
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect SSRF vulnerabilities
    assert!(result.issues.len() > 0);
    
    let ssrf_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_ssrf"))
        .collect();
    
    assert!(ssrf_issues.len() >= 3, "Should detect multiple SSRF patterns");
}

#[test]
fn test_python_path_traversal() {
    // Issue #361: Path traversal vulnerabilities
    let python_content = r#"
import os
from flask import Flask, request, send_from_directory, send_file

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    
    # Vulnerable: send_from_directory with user input
    return send_from_directory('/uploads', filename)

@app.route('/read')  
def read_file():
    filepath = request.form.get('filepath')
    
    # Vulnerable: open file with user input
    with open(f"./files/{filepath}", 'r') as f:
        content = f.read()
    
    # Vulnerable: os.path.join with user input  
    user_file = request.args.get('file')
    full_path = os.path.join('/uploads', user_file)
    return send_file(full_path)

@app.route('/upload')
def upload():
    filename = request.args.get('name')
    # Vulnerable: path construction with user input
    save_path = f"/tmp/{filename}"
    with open(save_path, 'w') as f:
        f.write("data")
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect path traversal vulnerabilities
    assert!(result.issues.len() > 0);
    
    let path_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_path_traversal"))
        .collect();
    
    assert!(path_issues.len() >= 3, "Should detect multiple path traversal patterns");
}

#[test]
fn test_python_weak_authentication() {
    // Issue #376: Weak authentication patterns
    let python_content = r#"
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "secret"  # Vulnerable: weak secret key

# Vulnerable: hardcoded credentials
admin_password = "admin123"
API_KEY = "test-key-123"

@app.route('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Vulnerable: plain text password comparison
    if password == admin_password:
        session['authenticated'] = True
        return "Login successful"
    
    # Vulnerable: weak password validation
    if len(password) < 6:
        return "Password too short"
        
    return "Login failed"

@app.route('/admin')  
def admin_panel():
    # Vulnerable: missing authentication check
    return "Admin dashboard"

# Vulnerable: debug mode in production
app.run(debug=True)
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect weak authentication issues
    assert!(result.issues.len() > 0);
    
    let auth_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_weak_authentication"))
        .collect();
    
    assert!(auth_issues.len() >= 4, "Should detect multiple authentication weaknesses");
}

#[test]
fn test_python_nosql_injection() {
    // Issue #389: NoSQL injection vulnerabilities
    let python_content = r#"
from pymongo import MongoClient
from flask import Flask, request

app = Flask(__name__)
client = MongoClient()
db = client.myapp

@app.route('/users')
def find_users():
    username = request.args.get('username')
    
    # Vulnerable: NoSQL injection via f-string
    query = f'{{"name": "{username}"}}'
    users = db.users.find(query)
    
    # Vulnerable: $where operator with user input
    condition = request.form.get('condition')
    result = db.users.find({"$where": condition})
    
    # Vulnerable: direct user input in find()
    user_filter = request.json.get('filter')
    data = db.collection.find(user_filter)
    
    return str(list(users))

@app.route('/search')
def search():
    pattern = request.args.get('pattern')
    # Vulnerable: regex injection
    query = f'{{"name": {{"$regex": "{pattern}"}}}}'
    results = db.users.find(query)
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect NoSQL injection vulnerabilities
    assert!(result.issues.len() > 0);
    
    let nosql_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_nosql_injection"))
        .collect();
    
    assert!(nosql_issues.len() >= 2, "Should detect NoSQL injection patterns");
}

#[test]
fn test_python_xxe() {
    // Issue #380, #363: XXE vulnerabilities  
    let python_content = r#"
import xml.etree.ElementTree as ET
from flask import Flask, request
from lxml import etree
import xml.dom.minidom as minidom

app = Flask(__name__)

@app.route('/parse')
def parse_xml():
    xml_data = request.data
    
    # Vulnerable: ET.parse with user input
    root = ET.parse(xml_data)
    
    # Vulnerable: ET.fromstring with user input
    xml_string = request.form.get('xml')
    parsed = ET.fromstring(xml_string)
    
    # Vulnerable: lxml parsing
    doc = etree.parse(xml_data)
    
    # Vulnerable: minidom parsing
    dom = minidom.parseString(xml_string)
    
    return "Parsed successfully"

@app.route('/generate')
def generate_xml():
    user_data = request.args.get('data')
    
    # Vulnerable: XML injection via f-string
    xml_response = f"<response>{user_data}</response>"
    
    # Vulnerable: XML attribute injection
    attr_value = request.form.get('attr')
    xml_with_attr = f'<element id="{attr_value}">content</element>'
    
    return xml_response
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect XXE vulnerabilities
    assert!(result.issues.len() > 0);
    
    let xxe_issues: Vec<_> = result.issues.iter()
        .filter(|issue| issue.rule.as_ref().map_or(false, |rule| rule == "python_xxe"))
        .collect();
    
    assert!(xxe_issues.len() >= 4, "Should detect XXE and XML injection patterns");
}

#[test]
fn test_python_weak_cryptography() {
    // Issue #373: Weak cryptography
    let python_content = r#"
import hashlib
import random
import md5
import jwt

# Vulnerable: MD5 for password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerable: SHA1 for security
def generate_token(user_id):
    return hashlib.sha1(str(user_id).encode()).hexdigest()

# Vulnerable: weak random number generation for security
def create_session_id():
    return str(random.randint(1000, 9999))

# Vulnerable: weak JWT secret
JWT_SECRET = "secret"

def create_jwt(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# Vulnerable: no signature verification
def verify_jwt(token):
    return jwt.decode(token, verify=False)

# Vulnerable: hardcoded encryption key
ENCRYPTION_KEY = b"1234567890123456"

def encrypt_data(data):
    # Using deprecated DES would be detected by import analysis
    pass
"#;

    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(&PathBuf::from("app.py"), python_content);
    
    // Should detect weak cryptography
    assert!(result.issues.len() > 0);
    
    let crypto_issues: Vec<_> = result.issues.iter()
        .filter(|issue| {
            issue.rule.as_ref().map_or(false, |rule| {
                rule == "python_weak_cryptography" || rule == "python_jwt_weakness"
            })
        })
        .collect();
    
    assert!(crypto_issues.len() >= 5, "Should detect weak cryptography patterns");
}