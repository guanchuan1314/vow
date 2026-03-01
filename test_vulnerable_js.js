// Test cases for JavaScript security vulnerabilities

// XSS vulnerabilities
app.get('/user', (req, res) => {
    const username = req.query.username;
    res.send(`<h1>Welcome ${username}!</h1>`); // Vulnerable to XSS
});

// SQL Injection with template literals
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`; // Vulnerable to SQL injection
    db.query(query);
});

// NoSQL Injection
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    User.findOne({ username, password }); // Vulnerable to NoSQL injection
});

// Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.file;
    const filePath = path.join(__dirname, 'uploads', filename); // Vulnerable to path traversal
    res.sendFile(filePath);
});

// Server-Side Template Injection (SSTI)
app.get('/template', (req, res) => {
    const data = req.query;
    res.render('template', data); // Vulnerable to SSTI
});

// Open Redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url); // Vulnerable to open redirect
});

// CSRF - Missing CSRF protection
app.post('/transfer', (req, res) => {
    const { to, amount } = req.body;
    // No CSRF token validation - vulnerable to CSRF
    transferMoney(to, amount);
});

// IDOR - Insecure Direct Object Reference
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    User.findById(userId); // Vulnerable to IDOR - no authorization check
});

// Mass Assignment
app.post('/user', (req, res) => {
    const user = new User(req.body); // Vulnerable to mass assignment
    user.save();
});