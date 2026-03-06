use std::path::Path;
use vow::analyzers::code::CodeAnalyzer;

fn check(filename: &str, code: &str, expected_rule: &str) -> bool {
    let analyzer = CodeAnalyzer::new();
    let result = analyzer.analyze(Path::new(filename), code);
    result
        .issues
        .iter()
        .any(|i| i.rule.as_deref() == Some(expected_rule))
}

// #500: XSS via res.send() with template literals
#[test]
fn test_ts_express_xss_res_send() {
    let code = r#"
app.get('/greet', (req, res) => {
    res.send(`<h1>Hello ${req.query.name}</h1>`);
});
"#;
    assert!(check("app.ts", code, "ts_express_xss_res_send"));
}

#[test]
fn test_ts_express_xss_res_send_concat() {
    let code = r#"
app.get('/greet', (req, res) => {
    res.send("<div>" + req.query.name + "</div>");
});
"#;
    assert!(check("app.ts", code, "ts_express_xss_res_send_concat"));
}

// #501: Path traversal
#[test]
fn test_ts_express_path_traversal() {
    let code = r#"
app.get('/file', (req, res) => {
    const filePath = path.join(__dirname, 'files', req.query.name);
    fs.readFile(filePath, (err, data) => res.send(data));
});
"#;
    assert!(check("app.ts", code, "ts_express_path_traversal_join"));
}

// #502: SSRF via axios
#[test]
fn test_ts_express_ssrf_axios() {
    let code = r#"
app.post('/fetch', async (req, res) => {
    const response = await axios.get(req.body.url);
    res.json(response.data);
});
"#;
    assert!(check("app.ts", code, "ts_express_ssrf_axios"));
}

// #503/#518: Open redirect
#[test]
fn test_ts_express_open_redirect() {
    let code = r#"
app.get('/redirect', (req, res) => {
    res.redirect(req.query.url);
});
"#;
    assert!(check("app.ts", code, "ts_express_open_redirect"));
}

// #504: Insecure deserialization
#[test]
fn test_ts_express_insecure_deserialization() {
    let code = r#"
app.post('/login', (req, res) => {
    const user = JSON.parse(req.body.user);
    if (user.isAdmin) { grantAccess(); }
});
"#;
    assert!(check("app.ts", code, "ts_express_insecure_deserialization"));
}

// #505/#526: Template injection / SSTI
#[test]
fn test_ts_express_ssti_render() {
    let code = r#"
app.get('/page', (req, res) => {
    res.render(req.query.template, { data: 'hello' });
});
"#;
    assert!(check("app.ts", code, "ts_express_ssti_render"));
}

// #506: Mass assignment
#[test]
fn test_ts_express_mass_assignment_spread() {
    let code = r#"
app.post('/user', (req, res) => {
    const user = { ...req.body };
    db.users.create(user);
});
"#;
    assert!(check("app.ts", code, "ts_express_mass_assignment_spread"));
}

#[test]
fn test_ts_express_mass_assignment_assign() {
    let code = r#"
app.put('/user/:id', (req, res) => {
    Object.assign(user, req.body);
    user.save();
});
"#;
    assert!(check("app.ts", code, "ts_express_mass_assignment_assign"));
}

// #507: IDOR
#[test]
fn test_ts_express_idor_findbyid() {
    let code = r#"
app.get('/user/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);
});
"#;
    assert!(check("app.ts", code, "ts_express_idor_findbyid"));
}

// #508: Buffer overflow
#[test]
fn test_ts_express_buffer_overflow() {
    let code = "Buffer.alloc(1024).write(largeInput);\n";
    assert!(check("app.ts", code, "ts_express_buffer_overflow"));
}

// #510: Prototype pollution
#[test]
fn test_ts_express_prototype_pollution() {
    let code = r#"
app.post('/config', (req, res) => {
    Object.assign(User.prototype, req.body);
});
"#;
    assert!(check("app.ts", code, "ts_express_prototype_pollution"));
}

// #512: Insecure randomness
#[test]
fn test_ts_express_insecure_random() {
    let code = r#"
const token = Math.random().toString(36).substring(2);
"#;
    assert!(check("app.ts", code, "ts_express_insecure_random_reverse"));
}

// #513: Weak cryptography
#[test]
fn test_ts_express_weak_crypto_md5() {
    let code = r#"
const hash = crypto.createHash('md5').update(password).digest('hex');
"#;
    assert!(check("app.ts", code, "ts_express_weak_crypto_md5"));
}

// #514: Missing rate limiting
#[test]
fn test_ts_express_no_rate_limit() {
    let code = r#"
app.post('/login', (req, res) => {
    authenticate(req.body.username, req.body.password);
});
"#;
    assert!(check("app.ts", code, "ts_express_no_rate_limit_login"));
}

// #515: Missing CSP
#[test]
fn test_ts_express_no_csp() {
    let code = r#"
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html><html><body>Hello</body></html>`);
});
"#;
    assert!(check("app.ts", code, "ts_express_no_csp"));
}

// #516: Weak authentication
#[test]
fn test_ts_express_hardcoded_creds() {
    let code = r#"
if (password === 'admin123' && username === 'admin') {
    grantAccess();
}
"#;
    assert!(check("app.ts", code, "ts_express_hardcoded_creds"));
}

// #517: Unrestricted file upload
#[test]
fn test_ts_express_unrestricted_upload() {
    let code = r#"
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.any(), (req, res) => {});
"#;
    assert!(check("app.ts", code, "ts_express_unrestricted_upload"));
}

// #519: XML injection
#[test]
fn test_ts_express_xml_injection() {
    let code = r#"
app.post('/parse', (req, res) => {
    parseString(req.body.xml, (err, result) => {
        res.json(result);
    });
});
"#;
    assert!(check("app.ts", code, "ts_express_xml_injection"));
}

// #520: LDAP injection
#[test]
fn test_ts_express_ldap_injection() {
    let code = r#"
app.post('/search', (req, res) => {
    const filter = `(uid=${req.body.username})`;
    client.search(baseDN, { filter });
});
"#;
    assert!(check("app.ts", code, "ts_express_ldap_injection_filter"));
}

// #524: CRLF injection
#[test]
fn test_ts_express_crlf_injection() {
    let code = r#"
app.get('/download', (req, res) => {
    res.download(filePath, req.query.filename);
});
"#;
    assert!(check("app.ts", code, "ts_express_crlf_injection"));
}

// #525: HTTP request smuggling
#[test]
fn test_ts_express_http_smuggling() {
    let code = r#"
app.use((req, res, next) => {
    const te = req.headers['transfer-encoding'];
    proxy.setHeader('Transfer-Encoding', te);
});
"#;
    assert!(check("app.ts", code, "ts_express_http_smuggling"));
}

// Verify patterns don't match on Python files
#[test]
fn test_ts_express_no_match_python() {
    let code = r#"
app.get('/greet', (req, res) => {
    res.send(`<h1>Hello ${req.query.name}</h1>`);
});
"#;
    assert!(!check("app.py", code, "ts_express_xss_res_send"));
}
