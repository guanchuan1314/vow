use std::path::Path;
use std::collections::HashSet;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomAllowlist {
    pub python: Option<Vec<String>>,
    pub javascript: Option<Vec<String>>,
    pub java: Option<Vec<String>>,
    pub go: Option<Vec<String>>,
    pub ruby: Option<Vec<String>>,
    pub c: Option<Vec<String>>,
    pub cpp: Option<Vec<String>>,
    pub csharp: Option<Vec<String>>,
    pub php: Option<Vec<String>>,
    pub swift: Option<Vec<String>>,
    pub kotlin: Option<Vec<String>>,
    pub r: Option<Vec<String>>,
    pub mql5: Option<Vec<String>>,
    pub scala: Option<Vec<String>>,
    pub perl: Option<Vec<String>>,
    pub lua: Option<Vec<String>>,
    pub dart: Option<Vec<String>>,
    pub haskell: Option<Vec<String>>,
}

// Cached regex patterns for performance
static SECURITY_PATTERNS: Lazy<Vec<SecurityPattern>> = Lazy::new(|| vec![
    SecurityPattern {
        name: "eval_usage",
        regex: Regex::new(r"\beval\s*\(").unwrap(),
        severity: Severity::High,
        message: "Potentially dangerous eval() usage detected",
    },
    SecurityPattern {
        name: "exec_usage", 
        regex: Regex::new(r"\bexec\s*\(").unwrap(),
        severity: Severity::High,
        message: "Potentially dangerous exec() usage detected",
    },
    SecurityPattern {
        name: "system_calls",
        regex: Regex::new(r"(subprocess\.call|subprocess\.run|os\.system|os\.popen|shell_exec|system\(|exec\(|passthru\(|shell_exec\()").unwrap(),
        severity: Severity::Medium,
        message: "System call detected - verify input sanitization",
    },
    SecurityPattern {
        name: "hardcoded_secrets",
        regex: Regex::new(r#"(password|secret|key|token)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
        severity: Severity::High,
        message: "Potential hardcoded secret detected",
    },
    SecurityPattern {
        name: "api_keys",
        regex: Regex::new(r#"(API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY)\s*[=:]\s*["'][^"']+["']"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded API key or secret detected",
    },
    SecurityPattern {
        name: "rust_const_secrets",
        regex: Regex::new(r#"(?i)const\s+[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN|API)[A-Z_]*\s*:\s*&str\s*=\s*["'][^"']{8,}["']"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secret in Rust const declaration",
    },
    SecurityPattern {
        name: "rust_static_secrets",
        regex: Regex::new(r#"(?i)static\s+[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN|API)[A-Z_]*\s*:\s*&str\s*=\s*["'][^"']{8,}["']"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secret in Rust static declaration",
    },
    SecurityPattern {
        name: "sql_injection",
        regex: Regex::new(r#"(execute\(|query\(|sql\s*=)[^;]*\+[^;]*["']"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection vulnerability - string concatenation in SQL",
    },
    SecurityPattern {
        name: "shell_injection",
        regex: Regex::new(r"subprocess\.[^(]*\([^)]*shell\s*=\s*True").unwrap(),
        severity: Severity::High,
        message: "Shell injection risk - subprocess with shell=True",
    },
    SecurityPattern {
        name: "insecure_http",
        regex: Regex::new(r#"["']http://[^"'\s]+["']?"#).unwrap(),
        severity: Severity::Medium,
        message: "Insecure HTTP URL found - consider using HTTPS",
    },
    SecurityPattern {
        name: "rm_rf",
        regex: Regex::new(r"rm\s+-rf\s+").unwrap(),
        severity: Severity::Critical,
        message: "Dangerous rm -rf command detected",
    },
    SecurityPattern {
        name: "chmod_777",
        regex: Regex::new(r"chmod\s+(777|0777)").unwrap(),
        severity: Severity::High,
        message: "Dangerous chmod 777 permissions detected",
    },
    SecurityPattern {
        name: "ssl_verify_disabled",
        regex: Regex::new(r"(verify\s*=\s*False|SSL_VERIFYPEER.*false|curl_setopt.*CURLOPT_SSL_VERIFYPEER.*false)").unwrap(),
        severity: Severity::High,
        message: "SSL certificate verification disabled",
    },
    SecurityPattern {
        name: "dangerous_deserialize",
        regex: Regex::new(r"(pickle\.loads|pickle\.load|yaml\.load\(|eval\(|exec\()").unwrap(),
        severity: Severity::High,
        message: "Potentially unsafe deserialization method",
    },
    // Issue #3: YAML/config files hardcoded secrets
    SecurityPattern {
        name: "yaml_config_secrets",
        regex: Regex::new(r#"(?i)(password|secret|key|token|api_key|access_token|private_key|aws_secret|db_password):\s*['"]?[a-zA-Z0-9+/=]{8,}['"]?\s*$"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secret detected in YAML/JSON config file",
    },
    SecurityPattern {
        name: "env_file_secrets",
        regex: Regex::new(r#"(?i)^(PASSWORD|SECRET|KEY|TOKEN|API_KEY|ACCESS_TOKEN|PRIVATE_KEY|AWS_SECRET|DB_PASSWORD)\s*=\s*['"]?[a-zA-Z0-9+/=]{8,}['"]?\s*$"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secret detected in environment file",
    },
    // Issue #4: Enhanced SQL injection detection (multiple languages)
    SecurityPattern {
        name: "sql_injection_python",
        regex: Regex::new(r#"(cursor\.execute|execute|query)\s*\(\s*['"][^'"]*['"]\s*\+[^,)]*\+[^,)]*['"][^'"]*['"]"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Python - string concatenation in SQL query",
    },

    // Python/Flask vulnerability patterns
    // XSS in Flask
    SecurityPattern {
        name: "python_flask_xss",
        regex: Regex::new(r#"render_template_string\s*\([^)]*request\."#).unwrap(),
        severity: Severity::High,
        message: "XSS in Python/Flask - render_template_string with user input without escaping",
    },

    // Path traversal
    SecurityPattern {
        name: "python_path_traversal",
        regex: Regex::new(r#"os\.path\.join\s*\([^)]*request\.|pathlib\.[A-Z][a-z]+\([^)]*request\."#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Python - user input in file path without sanitization",
    },

    // SSRF
    SecurityPattern {
        name: "python_ssrf",
        regex: Regex::new(r#"requests\.(get|post|put|delete|head|patch)\s*\(\s*request\."#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Python - requests with user-controlled URL",
    },

    // Template injection (SSTI)
    SecurityPattern {
        name: "python_template_injection",
        regex: Regex::new(r#"render_template_string\s*\(\s*f["']"#).unwrap(),
        severity: Severity::Critical,
        message: "Template injection (SSTI) in Python - render_template_string with f-string user input",
    },

    // Jinja2 SSTI - from_string with user input
    SecurityPattern {
        name: "python_jinja2_ssti",
        regex: Regex::new(r#"jinja2\.Environment\.\w*from_string|from_string\s*\([^)]*request|from_string\s*\([^)]*f["']"#).unwrap(),
        severity: Severity::Critical,
        message: "Jinja2 SSTI in Python - from_string with user input can lead to RCE",
    },

    // XML injection
    SecurityPattern {
        name: "python_xml_injection",
        regex: Regex::new(r#"ET\.fromstring\s*\(\s*request\.|xml\.parse\s*\(\s*request\."#).unwrap(),
        severity: Severity::High,
        message: "XML injection in Python - parsing user XML without safe settings",
    },

    // Open redirect
    SecurityPattern {
        name: "python_flask_redirect",
        regex: Regex::new(r#"redirect\s*\(\s*request\."#).unwrap(),
        severity: Severity::Medium,
        message: "Open redirect in Python/Flask - redirect with user-controlled URL",
    },
    SecurityPattern {
        name: "python_fastapi_redirect",
        regex: Regex::new(r#"RedirectResponse\s*\(\s*[^,)]*request|redirect\s*\(\s*[^,)]*request"#).unwrap(),
        severity: Severity::Medium,
        message: "Unvalidated redirect in Python/FastAPI - RedirectResponse with user-controlled URL",
    },

    // Header injection
    SecurityPattern {
        name: "python_header_injection",
        regex: Regex::new(r#"response\.headers\[[^\]]*\]\s*=.*request\."#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Python - user input in HTTP headers without validation",
    },

    // Format string
    SecurityPattern {
        name: "python_format_string",
        regex: Regex::new(r#"(format\(|%s|\{request\.)"#).unwrap(),
        severity: Severity::Medium,
        message: "Format string vulnerability in Python - user input as format string operand",
    },

    // XPath injection
    SecurityPattern {
        name: "python_xpath_injection",
        regex: Regex::new(r#"xpath\([^)]*request\.|etree\.xpath\s*\([^)]*request\."#).unwrap(),
        severity: Severity::High,
        message: "XPath injection in Python - user input in XPath query",
    },

    // Unsafe file upload
    SecurityPattern {
        name: "python_unsafe_upload",
        regex: Regex::new(r#"file\.filename\s*=\s*request\.|upload_folder\s*=.*request\."#).unwrap(),
        severity: Severity::High,
        message: "Unsafe file upload in Python - user-controlled filename without validation",
    },

    // XXE injection
    SecurityPattern {
        name: "python_xxe",
        regex: Regex::new(r#"XMLParser\s*\(\s*\)|lxml\.etree\.XMLParser\s*\(\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "XXE injection in Python - XMLParser without XXE protection",
    },

    // FastAPI-specific patterns
    // XSS in FastAPI
    SecurityPattern {
        name: "python_fastapi_xss",
        regex: Regex::new(r#"HTMLResponse\s*\([^)]*f["']"#).unwrap(),
        severity: Severity::High,
        message: "XSS in Python/FastAPI - HTMLResponse with f-string user input",
    },

    // Path traversal in FastAPI
    SecurityPattern {
        name: "python_fastapi_path_traversal",
        regex: Regex::new(r#"os\.path\.join\s*\([^)]*(?:request|param)"#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Python/FastAPI - file operation with user input",
    },

    // SSRF in FastAPI (httpx)
    SecurityPattern {
        name: "python_fastapi_ssrf",
        regex: Regex::new(r#"httpx\.[a-zA-Z]+\s*\(\s*(?:request|url|param)"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Python/FastAPI - httpx with user-controlled URL",
    },

    // LDAP injection in FastAPI
    SecurityPattern {
        name: "python_fastapi_ldap_injection",
        regex: Regex::new(r#"f["'].*?\{(?:request|param)"#).unwrap(),
        severity: Severity::High,
        message: "LDAP injection in Python - f-string user input in query",
    },

    SecurityPattern {
        name: "sql_injection_php",
        regex: Regex::new(r#"(mysql_query|mysqli_query|query)\s*\(\s*['"][^'"]*['"]\s*\.\s*\$[^;)]*\s*\.\s*['"][^'"]*['"]"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in PHP - string concatenation in SQL query",
    },
    SecurityPattern {
        name: "sql_injection_js",
        regex: Regex::new(r#"(query|execute)\s*\(\s*['"][^'"]*['"]\s*\+[^,)]*\+[^,)]*['"][^'"]*['"]"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in JavaScript - string concatenation in SQL query",
    },
    SecurityPattern {
        name: "sql_injection_java",
        regex: Regex::new(r#"(executeQuery|executeUpdate|execute)\s*\(\s*['"][^'"]*['"]\s*\+[^,)]*\+[^,)]*['"][^'"]*['"]"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Java - string concatenation in SQL query",
    },
    SecurityPattern {
        name: "sql_injection_go",
        regex: Regex::new(r#"(Query|Exec)\s*\(\s*['"][^'"]*['"]\s*\+[^,)]*\+[^,)]*['"][^'"]*['"]"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Go - string concatenation in SQL query",
    },
    SecurityPattern {
        name: "sql_injection_ruby",
        regex: Regex::new(r#"where\s*\([^)]*\+\s*params"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Ruby - string concatenation in SQL query",
    },

    // Ruby/Rails vulnerability patterns
    // XSS in ERB
    SecurityPattern {
        name: "ruby_xss_erb",
        regex: Regex::new(r#"<%=\s*[^%]*params\[[^\]]+\]|<%=\s*[^%]*request\.[a-z_]+|<%=\s*[^%]*\[params"#).unwrap(),
        severity: Severity::High,
        message: "XSS in Ruby/Rails - unescaped user input in ERB template",
    },

    // Path traversal
    SecurityPattern {
        name: "ruby_path_traversal",
        regex: Regex::new(r#"(?:File\.read|File\.open|File\.join|readfile)\s*\([^)]*params\["#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Ruby/Rails - user input in file operation without sanitization",
    },

    // SSRF
    SecurityPattern {
        name: "ruby_ssrf",
        regex: Regex::new(r#"(?:Net::HTTP|RestClient|URI\.open|URI\.parse)\s*\(.*?params"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Ruby/Rails - user-controlled URL in HTTP request",
    },

    // YAML deserialization
    SecurityPattern {
        name: "ruby_yaml_load",
        regex: Regex::new(r#"YAML\.load\s*\(\s*params"#).unwrap(),
        severity: Severity::Critical,
        message: "YAML deserialization in Ruby - YAML.load with user input; use YAML.safe_load",
    },

    // XXE
    SecurityPattern {
        name: "ruby_xxe",
        regex: Regex::new(r#"Nokogiri::XML\s*\([^)]*\(params|XML\s*\(\s*\.open\("#).unwrap(),
        severity: Severity::High,
        message: "XXE vulnerability in Ruby - Nokogiri parsing XML from user input without safe settings",
    },

    // Template injection (ERB)
    SecurityPattern {
        name: "ruby_template_injection",
        regex: Regex::new(r#"ERB\.new\s*\(\s*params\["#).unwrap(),
        severity: Severity::Critical,
        message: "Template injection in Ruby - ERB.new with user input; can lead to RCE",
    },

    // Insecure deserialization
    SecurityPattern {
        name: "ruby_insecure_deserialization",
        regex: Regex::new(r#"Marshal\.load\s*\(\s*(?:params|request|cookies|session)"#).unwrap(),
        severity: Severity::Critical,
        message: "Insecure deserialization in Ruby - Marshal.load with user input can lead to RCE",
    },

    // Additional Ruby/Rails patterns
    // LDAP injection
    SecurityPattern {
        name: "ruby_ldap_injection",
        regex: Regex::new(r#"LDAP\.[a-z_]+\s*\(\s*params\["#).unwrap(),
        severity: Severity::High,
        message: "LDAP injection in Ruby/Rails - user input in LDAP filter without sanitization",
    },

    // Header injection
    SecurityPattern {
        name: "ruby_header_injection",
        regex: Regex::new(r#"headers\[[^\]]*\]\s*=\s*params\["#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Ruby/Rails - user input in HTTP headers without validation",
    },

    // Open redirect
    SecurityPattern {
        name: "ruby_open_redirect",
        regex: Regex::new(r#"redirect_to\s+params\["#).unwrap(),
        severity: Severity::Medium,
        message: "Open redirect in Ruby/Rails - redirect_to with user-controlled URL",
    },

    // Mass assignment
    SecurityPattern {
        name: "ruby_mass_assignment",
        regex: Regex::new(r#"\w+\.create\s*\(\s*params\[:\w+\]"#).unwrap(),
        severity: Severity::Medium,
        message: "Mass assignment in Ruby/Rails - Model.create with params without strong parameters",
    },

    // Unsafe file upload
    SecurityPattern {
        name: "ruby_unsafe_upload",
        regex: Regex::new(r#"(?:params|upload)\[:\w+\]\[:filename\]"#).unwrap(),
        severity: Severity::High,
        message: "Unsafe file upload in Ruby/Rails - user-controlled filename without sanitization",
    },

    // ReDoS
    SecurityPattern {
        name: "ruby_redos",
        regex: Regex::new(r#"Regexp\.new\s*\(\s*params\["#).unwrap(),
        severity: Severity::High,
        message: "ReDoS in Ruby - user-controlled input in Regexp can cause denial of service",
    },
    // Issue #5: Shell script hardcoded secrets
    SecurityPattern {
        name: "shell_hardcoded_secrets",
        regex: Regex::new(r#"(?i)^(PASSWORD|API_KEY|TOKEN|AWS_SECRET|DB_PASSWORD|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY)\s*=\s*['"]?[a-zA-Z0-9+/=]{8,}['"]?\s*$"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secret detected in shell script",
    },
    // Issue #6: curl|bash and wget|sh pipe patterns
    SecurityPattern {
        name: "remote_script_pipe",
        regex: Regex::new(r"(curl|wget)\s+[^|]*\|\s*(bash|sh|zsh|fish)").unwrap(),
        severity: Severity::Critical,
        message: "Dangerous remote script piping to shell (curl|bash or wget|sh)",
    },
    SecurityPattern {
        name: "curl_bash_oneliner",
        regex: Regex::new(r"curl\s+[^|]*https?://[^|]*\s*\|\s*bash").unwrap(),
        severity: Severity::Critical,
        message: "Dangerous curl | bash pattern detected - executing remote script",
    },
    SecurityPattern {
        name: "wget_sh_oneliner",
        regex: Regex::new(r"wget\s+[^|]*https?://[^|]*\s*\|\s*sh").unwrap(),
        severity: Severity::Critical,
        message: "Dangerous wget | sh pattern detected - executing remote script",
    },
    
    // Shell security vulnerabilities - Issue #X: Reverse shell detection
    SecurityPattern {
        name: "reverse_shell_bash_i",
        regex: Regex::new(r"(?i)bash\s+-i\s+.*?\/dev\/tcp").unwrap(),
        severity: Severity::Critical,
        message: "Reverse shell detected - bash -i with /dev/tcp",
    },
    SecurityPattern {
        name: "reverse_shell_nc_e",
        regex: Regex::new(r"(?i)nc\s+-[elvp]\s+\d+\s+.*?(/bin/sh|bash|-i)").unwrap(),
        severity: Severity::Critical,
        message: "Reverse shell detected - netcat with -e flag executing shell",
    },
    SecurityPattern {
        name: "reverse_shell_perl",
        regex: Regex::new(r"(?i)perl\s+.*?[^-]*-e\s+.*?socket").unwrap(),
        severity: Severity::Critical,
        message: "Reverse shell detected - Perl socket-based reverse shell",
    },
    SecurityPattern {
        name: "reverse_shell_python",
        regex: Regex::new(r"(?i)python.*?socket\.connect").unwrap(),
        severity: Severity::Critical,
        message: "Reverse shell detected - Python socket connection",
    },
    SecurityPattern {
        name: "reverse_shell_rm_nc",
        regex: Regex::new(r"(?i)rm\s+/tmp/f.*?;.*?mkfifo\s+.*?nc\s+").unwrap(),
        severity: Severity::Critical,
        message: "Reverse shell detected - named pipe reverse shell pattern",
    },
    
    // Shell security: Cron injection
    SecurityPattern {
        name: "cron_injection",
        regex: Regex::new(r"(?i)(crontab|cron)\s+[^&]*&&?\s*\*\s*\*\s*\*").unwrap(),
        severity: Severity::High,
        message: "Potential cron injection - dynamic command in cron expression",
    },
    SecurityPattern {
        name: "cron_write_crontab",
        regex: Regex::new(r"(?i)(echo|cat)\s+[^>]*>\s*\/etc\/crontabs?").unwrap(),
        severity: Severity::High,
        message: "Potential cron hijacking - direct crontab file modification",
    },
    SecurityPattern {
        name: "ssh_key_injection",
        regex: Regex::new(r"(?i)(echo|cat)\s+[^>]*>>\s*~?\/.ssh\/authorized_keys").unwrap(),
        severity: Severity::Critical,
        message: "SSH backdoor detected - adding key to authorized_keys",
    },
    
    // Shell security: Eval with user input
    SecurityPattern {
        name: "shell_eval_injection",
        regex: Regex::new(r"(?i)\beval\s+").unwrap(),
        severity: Severity::High,
        message: "Shell eval injection - executing unvalidated user input",
    },
    SecurityPattern {
        name: "shell_backticks_injection",
        regex: Regex::new(r"`.*?\$").unwrap(),
        severity: Severity::High,
        message: "Command injection via backticks with variable",
    },
    SecurityPattern {
        name: "shell_unsafe_reflection",
        regex: Regex::new(r"(?i)^\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*$").unwrap(),
        severity: Severity::High,
        message: "Shell unsafe reflection - executing variable as command",
    },
    
    // Shell security: Insecure tempfile usage
    SecurityPattern {
        name: "insecure_temp_file",
        regex: Regex::new(r"(?i)\/tmp\/[a-zA-Z0-9_]+\s+(cat|echo|grep|chmod|chown)").unwrap(),
        severity: Severity::Medium,
        message: "Insecure temp file usage - race condition possible",
    },
    
    // Shell security: sudo without password
    SecurityPattern {
        name: "sudo_nopasswd",
        regex: Regex::new(r"(?i)sudo\s+[^&]*NOPASSWD").unwrap(),
        severity: Severity::High,
        message: "sudo without password - privilege escalation risk",
    },
    
    // Shell security: Insecure network commands
    SecurityPattern {
        name: "insecure_telnet",
        regex: Regex::new(r"(?i)telnet\s+").unwrap(),
        severity: Severity::High,
        message: "Insecure protocol - telnet sends data in plain text",
    },
    SecurityPattern {
        name: "insecure_ftp",
        regex: Regex::new(r"(?i)(ftp\s+|lftp\s+|wget\s+.*?ftp:|curl\s+.*?ftp:)").unwrap(),
        severity: Severity::High,
        message: "Insecure protocol - FTP transmits credentials in plain text",
    },
    SecurityPattern {
        name: "insecure_rsh",
        regex: Regex::new(r"(?i)(rsh|rexec|rlogin)\s+").unwrap(),
        severity: Severity::High,
        message: "Insecure remote shell - rsh/rexec/rlogin are unencrypted",
    },
    
    // Shell security: Weak cryptography
    SecurityPattern {
        name: "shell_weak_crypto",
        regex: Regex::new(r"(?i)(openssl\s+.*?des|openssl\s+.*?md5|openssl\s+.*?sha1|\$\(.*?md5sum|\$\(.*?sha1sum)").unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in shell - using deprecated algorithm (DES/MD5/SHA1)",
    },
    
    // Shell security: Path traversal
    SecurityPattern {
        name: "shell_path_traversal",
        regex: Regex::new(r"(?i)(cat|rm|chmod|chown|wget|curl|open|read)\s+.*?\/.*?\$[a-zA-Z_]").unwrap(),
        severity: Severity::High,
        message: "Shell path traversal - unsanitized user input in file path",
    },
    
    // Shell security: SSRF (curl/wget with user URL)
    SecurityPattern {
        name: "shell_ssrf",
        regex: Regex::new(r"(?i)(curl|wget)\s+.*?\$[a-zA-Z_]").unwrap(),
        severity: Severity::High,
        message: "Shell SSRF - curl/wget with user-controlled URL",
    },
    
    // Shell security: Rate limiting (for API-like scripts)
    SecurityPattern {
        name: "shell_missing_rate_limit",
        regex: Regex::new(r"(?i)(while\s+true|for\s+;;|until\s+false).*?(curl|wget|http)").unwrap(),
        severity: Severity::Medium,
        message: "Potential missing rate limiting - HTTP request in loop without sleep/throttle",
    },
    
    // Shell security: Command with untrusted input
    SecurityPattern {
        name: "shell_var_injection",
        regex: Regex::new(r"(?i)\$\{?[a-zA-Z_][a-zA-Z0-9_]*\}?\s*;&&\s*(rm|cat|chmod|chown|wget|curl)").unwrap(),
        severity: Severity::High,
        message: "Shell command injection - unvalidated variable in dangerous command",
    },
    
    // Issue #7: Path traversal vulnerabilities
    SecurityPattern {
        name: "path_traversal_open",
        regex: Regex::new(r#"(open|file_get_contents|include|require|readFile)\s*\(\s*[^,)]*\+[^,)]*\.\./[^,)]*"#).unwrap(),
        severity: Severity::High,
        message: "Potential path traversal vulnerability - user input concatenated with ../ in file operation",
    },
    SecurityPattern {
        name: "path_traversal_concatenation",
        regex: Regex::new(r#"(open|sendFile|readFile|writeFile|include|require)\s*\([^)]*\+[^)]*\$\w+[^)]*\)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential path traversal - user input concatenated in file path",
    },
    // Issue #8: SSRF (Server-Side Request Forgery)
    SecurityPattern {
        name: "ssrf_fetch",
        regex: Regex::new(r#"(fetch|axios\.get|http\.get|requests\.get|urllib\.request\.urlopen)\s*\([^)]*\+[^)]*\$\w+[^)]*\)"#).unwrap(),
        severity: Severity::High,
        message: "Potential SSRF vulnerability - user-controlled URL in HTTP request",
    },
    SecurityPattern {
        name: "ssrf_url_concat",
        regex: Regex::new(r#"(fetch|axios|requests|urllib)\.[^(]*\(\s*['"][^'"]*['"]\s*\+[^,)]*\+[^,)]*['"][^'"]*['"]"#).unwrap(),
        severity: Severity::High,
        message: "Potential SSRF vulnerability - URL concatenation with user input",
    },
    // Issue #9: Open redirect vulnerabilities
    SecurityPattern {
        name: "open_redirect",
        regex: Regex::new(r#"(redirect|sendRedirect|location\.href|window\.location)\s*\([^)]*\+[^)]*\$\w+[^)]*\)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential open redirect vulnerability - user input in redirect URL",
    },
    SecurityPattern {
        name: "location_redirect",
        regex: Regex::new(r#"(location\.href|window\.location)\s*=\s*[^;]*\+[^;]*\$\w+[^;]*"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential open redirect - user input in location assignment",
    },
    // Issue #10: Enhanced SSL/TLS bypass detection
    SecurityPattern {
        name: "node_tls_reject_disabled",
        regex: Regex::new(r#"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?"#).unwrap(),
        severity: Severity::High,
        message: "TLS certificate verification disabled via NODE_TLS_REJECT_UNAUTHORIZED=0",
    },
    SecurityPattern {
        name: "python_ssl_unverified_context",
        regex: Regex::new(r"ssl\._create_unverified_context").unwrap(),
        severity: Severity::High,
        message: "SSL certificate verification bypassed using _create_unverified_context",
    },
    SecurityPattern {
        name: "requests_verify_false",
        regex: Regex::new(r"requests\.[^(]*\([^)]*verify\s*=\s*False[^)]*\)").unwrap(),
        severity: Severity::High,
        message: "SSL certificate verification disabled in requests library",
    },
    SecurityPattern {
        name: "curl_insecure_ssl",
        regex: Regex::new(r"curl\s+[^-]*-k[^-]*|curl\s+[^-]*--insecure[^-]*").unwrap(),
        severity: Severity::High,
        message: "SSL certificate verification disabled in curl command",
    },
    // Issue #11: Prototype pollution vulnerabilities  
    SecurityPattern {
        name: "prototype_pollution_merge",
        regex: Regex::new(r"(merge|assign|extend)\s*\([^)]*\)[^{]*\{[^}]*\}").unwrap(),
        severity: Severity::Medium,
        message: "Potential prototype pollution - recursive merge/assign without __proto__ guards",
    },
    SecurityPattern {
        name: "prototype_pollution_unsafe",
        regex: Regex::new(r"(Object\.assign|_.merge|_.extend|Object\.setPrototypeOf)\s*\([^)]*\$\w+[^)]*\)").unwrap(),
        severity: Severity::High,
        message: "Potential prototype pollution - unsafe object merge with user input",
    },
    SecurityPattern {
        name: "proto_assignment",
        regex: Regex::new(r#"\[['"]__proto__['"]\]|\[['"]constructor['"]\]|\[['"]prototype['"]\]"#).unwrap(),
        severity: Severity::High,
        message: "Potential prototype pollution - direct __proto__/constructor/prototype assignment",
    },
    // Issue #12: XXE (XML External Entity) vulnerabilities in Java
    SecurityPattern {
        name: "java_xxe_documentbuilder",
        regex: Regex::new(r"DocumentBuilderFactory\.newInstance\(\)").unwrap(),
        severity: Severity::High,
        message: "Potential XXE vulnerability - DocumentBuilderFactory without secure processing features",
    },
    SecurityPattern {
        name: "java_xxe_saxparser",
        regex: Regex::new(r"SAXParserFactory\.newInstance\(\)").unwrap(),
        severity: Severity::High,
        message: "Potential XXE vulnerability - SAXParserFactory without secure processing features",
    },
    SecurityPattern {
        name: "java_xxe_xmlreader",
        regex: Regex::new(r"XMLReaderFactory\.createXMLReader\(\)").unwrap(),
        severity: Severity::High,
        message: "Potential XXE vulnerability - XMLReader without secure processing features",
    },
    SecurityPattern {
        name: "java_xxe_transformer",
        regex: Regex::new(r"TransformerFactory\.newInstance\(\)").unwrap(),
        severity: Severity::High,
        message: "Potential XXE vulnerability - TransformerFactory without secure processing features",
    },
    // Rust/Actix-specific vulnerability patterns (#14-#37)
    
    // Issue #14: SQL injection in Rust
    SecurityPattern {
        name: "rust_sql_injection_format",
        regex: Regex::new(r#"(?i)format!\s*\(\s*["'][^"']*SELECT[^"']*["']"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Rust - format! macro with user input in SQL query",
    },
    SecurityPattern {
        name: "rust_sql_injection_concat",
        regex: Regex::new(r#"(?i)(["'][^"']*SELECT[^"']*["'].*?\.to_string\(\).*?\+.*?&[a-zA-Z_][a-zA-Z0-9_]*)"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Rust - string concatenation in SQL query",
    },
    
    // Issue #15: XSS in Rust/Actix
    SecurityPattern {
        name: "rust_xss_format_html",
        regex: Regex::new(r#"(?i)format!\s*\(\s*["'][^"']*<[^"']*["']\s*,[^)]*[a-zA-Z_][a-zA-Z0-9_]*"#).unwrap(),
        severity: Severity::High,
        message: "Potential XSS in Rust - format! macro creating HTML with user input",
    },
    SecurityPattern {
        name: "rust_xss_actix_html",
        regex: Regex::new(r#"(?i)HttpResponse::Ok\(\)[^;]*content_type\s*\(\s*["']text/html["'][^;]*body\s*\([^)]*format!"#).unwrap(),
        severity: Severity::High,
        message: "Potential XSS in Actix - serving HTML with unescaped user input",
    },
    SecurityPattern {
        name: "rust_xss_script_injection",
        regex: Regex::new(r#"(?i)format!\s*\(\s*["'][^"']*<script[^"']*["']\s*,"#).unwrap(),
        severity: Severity::Critical,
        message: "Potential XSS in Rust - format! macro creating script tags with user input",
    },
    SecurityPattern {
        name: "rust_xss_string_concat",
        regex: Regex::new(r#"(?i)["'][^"']*<[^"']*["']\s*\.to_string\(\)\s*\+\s*&[a-zA-Z_][a-zA-Z0-9_]*"#).unwrap(),
        severity: Severity::High,
        message: "Potential XSS in Rust - HTML string concatenation with user input",
    },
    
    // Issue #19: XXE in Rust
    SecurityPattern {
        name: "rust_xxe_quick_xml",
        regex: Regex::new(r"(?i)(quick_xml::Reader::from_str|quick_xml::Reader::from_file)").unwrap(),
        severity: Severity::Medium,
        message: "Potential XXE vulnerability - XML parsing without external entity prevention",
    },
    SecurityPattern {
        name: "rust_xxe_xml_rs",
        regex: Regex::new(r"(?i)(xml::reader::EventReader|xml::ParserConfig)").unwrap(),
        severity: Severity::Medium,
        message: "Potential XXE vulnerability - xml-rs parsing without external entity configuration",
    },
    
    // Issue #20: Open redirect in Rust/Actix
    SecurityPattern {
        name: "rust_open_redirect_format",
        regex: Regex::new(r#"(?i)(format!\s*\(\s*["'][^"']*https?://[^"']*["']\s*,[^)]*\))"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential open redirect in Rust - format! macro with user input in URL",
    },
    SecurityPattern {
        name: "rust_actix_redirect",
        regex: Regex::new(r#"(?i)(HttpResponse::Found\(\)\.header\s*\(\s*["']location["'].*?format!)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential open redirect in Actix - redirect header with user input",
    },
    
    // Rust/Axum specific patterns
    // SQL injection in sqlx
    SecurityPattern {
        name: "rust_sqlx_injection",
        regex: Regex::new(r#"(?i)(sqlx::query|Query::new)\s*\(\s*format!"#).unwrap(),
        severity: Severity::High,
        message: "SQL injection in Rust/Axum - format! macro with user input in sqlx::query",
    },
    
    // XSS in Axum with Html
    SecurityPattern {
        name: "rust_axum_xss_html",
        regex: Regex::new(r#"(?i)axum::response::Html\s*\(\s*[^)]*req\."#).unwrap(),
        severity: Severity::High,
        message: "XSS in Axum - Html response with user input without escaping",
    },
    
    // SSRF in Rust reqwest
    SecurityPattern {
        name: "rust_reqwest_ssrf",
        regex: Regex::new(r#"(?i)(reqwest::Client|Client::new)\(\)[^;]*(?:\.get|\.post|\.put)\s*\(\s*&?[a-zA-Z_][a-zA-Z0-9_]*"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Rust - reqwest with user-controlled URL",
    },
    
    // Open redirect in Axum
    SecurityPattern {
        name: "rust_axum_redirect",
        regex: Regex::new(r#"(?i)(Redirect::to|Redirect::temporary|Redirect::permanent)\s*\(\s*&?[a-zA-Z_][a-zA-Z0-9_]*"#).unwrap(),
        severity: Severity::Medium,
        message: "Open redirect in Axum - Redirect with user-controlled URL",
    },
    
    // Issue #22: Eval-like injection in Rust
    SecurityPattern {
        name: "rust_eval_injection",
        regex: Regex::new(r"(?i)(std::process::Command::new\s*\([^)]*format!\s*\()").unwrap(),
        severity: Severity::High,
        message: "Potential eval injection in Rust - dynamic command execution with user input",
    },
    
    // Issue #23: Unsafe deserialization in Rust  
    SecurityPattern {
        name: "rust_unsafe_deserialization",
        regex: Regex::new(r"(?i)(serde_json::from_str|bincode::deserialize|ron::from_str)\s*\([^)]*&[a-zA-Z_][a-zA-Z0-9_]*").unwrap(),
        severity: Severity::Medium,
        message: "Potential unsafe deserialization in Rust - deserializing untrusted data",
    },
    SecurityPattern {
        name: "rust_pickle_equivalent",
        regex: Regex::new(r"(?i)(postcard::from_bytes|rmp_serde::from_slice|bincode::deserialize)").unwrap(),
        severity: Severity::High,
        message: "Rust deserialization with binary formats - equivalent to pickle, verify data source",
    },
    
    // Issue #24: Template injection in Rust
    SecurityPattern {
        name: "rust_template_injection_handlebars",
        regex: Regex::new(r"(?i)(handlebars\.render_template\s*\([^)]*&[a-zA-Z_][a-zA-Z0-9_]*)").unwrap(),
        severity: Severity::High,
        message: "Potential template injection in Rust - Handlebars rendering user input",
    },
    SecurityPattern {
        name: "rust_template_injection_tera",
        regex: Regex::new(r"(?i)(tera\.render\s*\([^)]*&[a-zA-Z_][a-zA-Z0-9_]*)").unwrap(),
        severity: Severity::High,
        message: "Potential template injection in Rust - Tera rendering user input",
    },
    
    // Issue #25: Mass assignment in Rust/Actix
    SecurityPattern {
        name: "rust_mass_assignment_serde",
        regex: Regex::new(r"(?i)(#\[derive\([^)]*Deserialize[^)]*\)\][^{]*pub\s+struct[^{]*\{)").unwrap(),
        severity: Severity::Low,
        message: "Potential mass assignment in Rust - Serde Deserialize without field filtering",
    },
    
    // Issue #26: CSRF in Actix 
    SecurityPattern {
        name: "rust_actix_csrf_missing",
        regex: Regex::new(r"(?i)(pub\s+async\s+fn\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*web::(Form|Json)[^)]*\)\s*->[^{]*\{[^}]*(delete|update|transfer|change))").unwrap(),
        severity: Severity::Medium,
        message: "Potential CSRF vulnerability in Actix - state-changing endpoint without CSRF protection",
    },
    
    // Issue #27: Insecure direct object reference in Rust/Actix
    SecurityPattern {
        name: "rust_idor_path_param",
        regex: Regex::new(r"(?i)(web::Path<[^>]*>\s*\)\s*->[^{]*\{[^}]*(?:SELECT|DELETE|UPDATE)[^}]*\{)").unwrap(),
        severity: Severity::Medium,
        message: "Potential IDOR in Rust - direct database access using path parameters",
    },
    
    // Issue #34: Format string vulnerability in Rust
    SecurityPattern {
        name: "rust_format_string_vuln",
        regex: Regex::new(r"(?i)(println!\s*\(\s*&[a-zA-Z_][a-zA-Z0-9_]*\s*\)|format!\s*\(\s*&[a-zA-Z_][a-zA-Z0-9_]*\s*\))").unwrap(),
        severity: Severity::Low,
        message: "Potential format string vulnerability in Rust - user input as format string",
    },
    
    // Issue #37: Side channel attacks in Rust
    SecurityPattern {
        name: "rust_timing_side_channel",
        regex: Regex::new(r"(?i)([a-zA-Z_][a-zA-Z0-9_]*\s*==\s*[a-zA-Z_][a-zA-Z0-9_]*.*?(password|secret|key|token|hash))").unwrap(),
        severity: Severity::Low,
        message: "Potential timing side-channel attack in Rust - non-constant time comparison of secrets",
    },
    
    // Issue #308: Insecure file permissions in Dart/Flutter
    SecurityPattern {
        name: "dart_insecure_filemode_0777",
        regex: Regex::new(r"FileMode\s*\(\s*0?777\s*\)").unwrap(),
        severity: Severity::High,
        message: "Insecure file permissions detected - FileMode(0777) grants world-writable access",
    },
    SecurityPattern {
        name: "dart_insecure_filemode_world_write",
        regex: Regex::new(r"FileMode\s*\(\s*0?[67][67][67]\s*\)").unwrap(),
        severity: Severity::High,
        message: "Insecure file permissions detected - world-writable FileMode",
    },
    SecurityPattern {
        name: "dart_setPermissions_777",
        regex: Regex::new(r"setPermissions\s*\(\s*FileMode\s*\(\s*0?777\s*\)\s*\)").unwrap(),
        severity: Severity::High,
        message: "Insecure file permissions detected - setPermissions with world-writable mode 777",
    },
    SecurityPattern {
        name: "dart_setPermissions_world_write",
        regex: Regex::new(r"setPermissions\s*\(\s*FileMode\s*\(\s*0?[67][67][67]\s*\)\s*\)").unwrap(),
        severity: Severity::High,
        message: "Insecure file permissions detected - setPermissions with world-writable permissions",
    },

    // Dart/Flutter vulnerability patterns
    // SQL injection
    SecurityPattern {
        name: "dart_sql_injection",
        regex: Regex::new(r#"(?:rawQuery|execute)\s*\(\s*['\"][^'\"]*\$\{[^}]+\}|['\"][^'\"]*\+[^;]*params"#).unwrap(),
        severity: Severity::High,
        message: "SQL injection in Dart/Flutter - string interpolation in rawQuery",
    },

    // Command injection
    SecurityPattern {
        name: "dart_command_injection",
        regex: Regex::new(r#"Process\.run\s*\([^)]*\+[^)]*params|Process\.runSync\s*\([^)]*\+[^)]*params"#).unwrap(),
        severity: Severity::High,
        message: "Command injection in Dart - user input in Process.run",
    },

    // Path traversal
    SecurityPattern {
        name: "dart_path_traversal",
        regex: Regex::new(r#"File\s*\(\s*[^)]*params\["#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Dart - user input in File path",
    },

    // SSRF
    SecurityPattern {
        name: "dart_ssrf",
        regex: Regex::new(r#"http\.(?:get|post|put|delete|head|patch)\s*\(\s*[^,)]*params"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Dart/Flutter - http request with user-controlled URL",
    },

    // XSS
    SecurityPattern {
        name: "dart_xss",
        regex: Regex::new(r#"Html\s*\(\s*['\"][^'\"]*\$\{[^}]+\}|Html\.escape\s*\(\s*params"#).unwrap(),
        severity: Severity::High,
        message: "XSS in Dart/Flutter - user input in HTML without escaping",
    },

    // Unsafe deserialization
    SecurityPattern {
        name: "dart_unsafe_deserialization",
        regex: Regex::new(r#"fromJson\s*\(\s*params|fromJson\s*\(\s*request\.body"#).unwrap(),
        severity: Severity::High,
        message: "Unsafe deserialization in Dart - fromJson with user input",
    },

    // Intent injection
    SecurityPattern {
        name: "dart_intent_injection",
        regex: Regex::new(r#"Process\.run\s*\(\s*['\"]am\s+start['\"][^)]*params"#).unwrap(),
        severity: Severity::High,
        message: "Intent injection in Dart/Flutter - Android intent with user input",
    },

    // Deeplink injection
    SecurityPattern {
        name: "dart_deeplink_injection",
        regex: Regex::new(r#"uri\.queryParameters\[[^\]]+\]\s*\+\s*['\"]|uri\.toString\s*\(\s*\)\s*\+\s*params"#).unwrap(),
        severity: Severity::Medium,
        message: "Deeplink injection in Dart - URI params used unsanitized",
    },

    // Additional Dart/Flutter patterns
    // Hardcoded secrets
    SecurityPattern {
        name: "dart_hardcoded_secrets",
        regex: Regex::new(r#"const\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\s*=\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secrets in Dart - API key or token in source code",
    },

    // Unsafe reflection
    SecurityPattern {
        name: "dart_unsafe_reflection",
        regex: Regex::new(r#"currentMirrorSystem|reflectClass|reflectInstance"#).unwrap(),
        severity: Severity::High,
        message: "Unsafe reflection in Dart - runtime reflection with user input",
    },

    // Insecure random
    SecurityPattern {
        name: "dart_insecure_random",
        regex: Regex::new(r#"Random\(\)\.nextInt|Random\.secure"#).unwrap(),
        severity: Severity::Medium,
        message: "Insecure random in Dart - Random() is not cryptographically secure",
    },

    // Buffer overflow (FFI)
    SecurityPattern {
        name: "dart_buffer_overflow",
        regex: Regex::new(r#"Pointer<[^>]*>\.fromAddress|malloc\("#).unwrap(),
        severity: Severity::High,
        message: "Buffer overflow risk in Dart - FFI pointer operations require bounds checking",
    },

    // Unsafe URI handling
    SecurityPattern {
        name: "dart_unsafe_uri",
        regex: Regex::new(r#"launchUrl\s*\(\s*[^)]*params|Uri\.parse\s*\(\s*params"#).unwrap(),
        severity: Severity::High,
        message: "Unsafe URI handling in Dart - user-controlled URL in launchUrl",
    },

    // Insecure webview navigation
    SecurityPattern {
        name: "dart_insecure_webview",
        regex: Regex::new(r#"WebViewController.*?loadRequest\s*\(\s*params"#).unwrap(),
        severity: Severity::High,
        message: "Insecure webview in Dart - WebView with user-controlled URL",
    },

    // Unvalidated redirect
    SecurityPattern {
        name: "dart_unvalidated_redirect",
        regex: Regex::new(r#"Navigator\.|push\([^)]*params\.|pushReplacement\([^)]*params\."#).unwrap(),
        severity: Severity::Medium,
        message: "Unvalidated redirect in Dart - navigation with user-controlled URL",
    },

    // Insecure asset access
    SecurityPattern {
        name: "dart_insecure_asset",
        regex: Regex::new(r#"rootBundle\.(loadString|load)\s*\(\s*params"#).unwrap(),
        severity: Severity::High,
        message: "Insecure asset access in Dart - user-controlled path in asset loading",
    },

    // Unsafe dynamic code loading
    SecurityPattern {
        name: "dart_dynamic_code",
        regex: Regex::new(r#"LibraryMirror|loadLibraryName|compute\s*\(\s*params"#).unwrap(),
        severity: Severity::High,
        message: "Unsafe dynamic code loading in Dart - executing user-supplied code",
    },

    // ReDoS
    SecurityPattern {
        name: "dart_redos",
        regex: Regex::new(r#"RegExp\s*\(\s*params\["#).unwrap(),
        severity: Severity::High,
        message: "ReDoS in Dart - user-controlled input in RegExp can cause denial of service",
    },

    // Unvalidated intent data
    SecurityPattern {
        name: "dart_unvalidated_intent",
        regex: Regex::new(r#"ReceiveSharingIntent"#).unwrap(),
        severity: Severity::Medium,
        message: "Unvalidated intent data in Dart - sharing intent data used without validation",
    },

    // Java/Servlet vulnerability patterns
    
    // #468: SQL injection via string concatenation in JDBC
    SecurityPattern {
        name: "java_servlet_sql_injection",
        regex: Regex::new(r#"(?i)executeQuery\s*\(\s*"[^"]*"\s*\+|executeQuery\s*\(\s*\w+\s*\+\s*"|\.createStatement\s*\(\s*\).*?executeQuery\s*\(\s*\w+\s*\)"#).unwrap(),
        severity: Severity::Critical,
        message: "SQL injection in Java Servlet - string concatenation in JDBC Statement.executeQuery()",
    },
    SecurityPattern {
        name: "java_servlet_sql_injection_concat",
        regex: Regex::new(r#"(?i)["']SELECT\s+.*?["']\s*\+\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::Critical,
        message: "SQL injection in Java Servlet - user input directly concatenated into SQL query",
    },
    // #469: XSS
    SecurityPattern {
        name: "java_servlet_xss",
        regex: Regex::new(r"(?i)getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write|format)\s*\([^)]*getParameter\s*\(").unwrap(),
        severity: Severity::High,
        message: "XSS in Java Servlet - unsanitized getParameter() output written to response",
    },
    SecurityPattern {
        name: "java_servlet_xss_variable",
        regex: Regex::new(r"(?i)(?:String\s+\w+\s*=\s*request\.getParameter\s*\([^)]*\)\s*;[^}]*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write))").unwrap(),
        severity: Severity::High,
        message: "XSS in Java Servlet - user input from getParameter() written to response without sanitization",
    },
    // #470: Path traversal
    SecurityPattern {
        name: "java_servlet_path_traversal",
        regex: Regex::new(r"(?i)new\s+File\s*\([^)]*getParameter\s*\(|new\s+FileInputStream\s*\([^)]*getParameter\s*\(").unwrap(),
        severity: Severity::High,
        message: "Path traversal in Java Servlet - user input in File/FileInputStream constructor",
    },
    // #471: SSRF
    SecurityPattern {
        name: "java_servlet_ssrf",
        regex: Regex::new(r"(?i)new\s+URL\s*\([^)]*getParameter\s*\([^)]*\)\s*\)\s*\.\s*openConnection").unwrap(),
        severity: Severity::High,
        message: "SSRF in Java Servlet - user-controlled URL in URL.openConnection()",
    },
    // #472: Open redirect / #487: Unvalidated redirect
    SecurityPattern {
        name: "java_servlet_open_redirect",
        regex: Regex::new(r"(?i)(?:response|res)\s*\.\s*sendRedirect\s*\([^)]*getParameter\s*\(").unwrap(),
        severity: Severity::Medium,
        message: "Open redirect in Java Servlet - user input in response.sendRedirect()",
    },
    // #473: Hardcoded secrets
    SecurityPattern {
        name: "java_hardcoded_password",
        regex: Regex::new(r#"(?i)(?:String\s+)?(?:password|passwd|pwd)\s*=\s*["'][^"']{4,}["']"#).unwrap(),
        severity: Severity::High,
        message: "Hardcoded password detected in Java source code",
    },
    SecurityPattern {
        name: "java_hardcoded_credential",
        regex: Regex::new(r#"(?i)(?:private\s+(?:static\s+)?(?:final\s+)?String\s+)(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|DB_PASSWORD|AUTH_TOKEN)\s*=\s*["'][^"']{4,}["']"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded credential/API key detected in Java source code",
    },
    // #474: Insecure deserialization
    SecurityPattern {
        name: "java_insecure_deserialization",
        regex: Regex::new(r"(?i)ObjectInputStream\s*\([^)]*\)\s*;[^}]*\.readObject\s*\(\s*\)").unwrap(),
        severity: Severity::Critical,
        message: "Insecure deserialization in Java - ObjectInputStream.readObject() on potentially untrusted data",
    },
    SecurityPattern {
        name: "java_insecure_deserialization_inline",
        regex: Regex::new(r"(?i)new\s+ObjectInputStream\s*\([^)]*(?:getInputStream|request|socket|input)").unwrap(),
        severity: Severity::Critical,
        message: "Insecure deserialization in Java - ObjectInputStream reading from user-controlled input stream",
    },
    // #475: CSRF
    SecurityPattern {
        name: "java_servlet_csrf_dopost",
        regex: Regex::new(r"(?i)(?:void\s+doPost\s*\(\s*HttpServletRequest)").unwrap(),
        severity: Severity::Medium,
        message: "Potential CSRF in Java Servlet - doPost() handler without visible CSRF token validation",
    },
    SecurityPattern {
        name: "java_servlet_csrf_post_handler",
        regex: Regex::new(r#"(?i)(?:if\s*\(\s*["']POST["']\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*request\s*\.\s*getMethod)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential CSRF in Java Servlet - POST handler without CSRF token validation",
    },
    // #499: GraphQL injection
    SecurityPattern {
        name: "java_graphql_injection",
        regex: Regex::new(r#"(?i)(?:ExecutionInput|graphql\.execute)\s*\([^)]*getParameter\s*\(|["'](?:query|mutation)\s*\{["']\s*\+\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::Critical,
        message: "GraphQL injection in Java - user input directly interpolated into GraphQL query",
    },
    SecurityPattern {
        name: "java_graphql_injection_concat",
        regex: Regex::new(r#"(?i)["'].*(?:query|mutation)\s+\w+.*["']\s*\+\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::High,
        message: "GraphQL injection in Java - string concatenation in GraphQL query construction",
    },
    // #498: NoSQL injection
    SecurityPattern {
        name: "java_nosql_injection",
        regex: Regex::new(r#"(?i)(?:BasicDBObject|Document)\s*\.\s*parse\s*\([^)]*getParameter\s*\(|MongoCollection.*find\s*\([^)]*getParameter"#).unwrap(),
        severity: Severity::Critical,
        message: "NoSQL injection in Java - user input in MongoDB query without sanitization",
    },
    SecurityPattern {
        name: "java_nosql_injection_string",
        regex: Regex::new(r#"(?i)["']\{[^"']*\w+\s*:[^"']*["']\s*\+\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::Critical,
        message: "NoSQL injection in Java - string concatenation in NoSQL query",
    },
    // #497: Second-order SQL injection
    SecurityPattern {
        name: "java_second_order_sqli",
        regex: Regex::new(r#"(?i)(?:executeQuery|executeUpdate|execute)\s*\(\s*["'][^"']*["']\s*\+\s*(?:rs\.getString|resultSet\.getString|result\.get)"#).unwrap(),
        severity: Severity::High,
        message: "Second-order SQL injection in Java - database-retrieved value used unsanitized in SQL query",
    },
    // #496: SSTI
    SecurityPattern {
        name: "java_ssti",
        regex: Regex::new(r#"(?i)(?:VelocityEngine|Velocity)\s*\.\s*evaluate\s*\([^)]*getParameter|(?:Freemarker|Configuration)\s*\.\s*(?:getTemplate|process)\s*\([^)]*getParameter"#).unwrap(),
        severity: Severity::Critical,
        message: "Server-side template injection (SSTI) in Java - user input in template engine evaluation",
    },
    SecurityPattern {
        name: "java_ssti_string_template",
        regex: Regex::new(r#"(?i)new\s+Template\s*\([^)]*getParameter|(?:template|engine)\s*\.\s*(?:merge|evaluate|process|render)\s*\([^)]*getParameter"#).unwrap(),
        severity: Severity::Critical,
        message: "Server-side template injection (SSTI) in Java - user input passed to template rendering",
    },
    // #494: CRLF injection
    SecurityPattern {
        name: "java_crlf_injection",
        regex: Regex::new(r#"(?i)(?:setHeader|addHeader|setStatus)\s*\([^)]*getParameter\s*\("#).unwrap(),
        severity: Severity::High,
        message: "CRLF injection in Java Servlet - user input in HTTP response header without sanitization",
    },
    SecurityPattern {
        name: "java_crlf_injection_cookie",
        regex: Regex::new(r#"(?i)new\s+Cookie\s*\([^)]*getParameter\s*\("#).unwrap(),
        severity: Severity::High,
        message: "CRLF injection in Java Servlet - user input in cookie value without sanitization",
    },
    // #489: LDAP injection
    SecurityPattern {
        name: "java_ldap_injection",
        regex: Regex::new(r#"(?i)(?:search|lookup)\s*\([^)]*getParameter\s*\(|(?:DirContext|InitialDirContext|LdapContext)\s*.*?search\s*\([^)]*\+\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::Critical,
        message: "LDAP injection in Java - user input in LDAP search query without sanitization",
    },
    SecurityPattern {
        name: "java_ldap_injection_filter",
        regex: Regex::new(r#"(?i)["']\(\w+=["']\s*\+\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::Critical,
        message: "LDAP injection in Java - user input concatenated into LDAP filter string",
    },
    // #488: XML injection
    SecurityPattern {
        name: "java_xml_injection",
        regex: Regex::new(r#"(?i)["']<\w+[^"']*["']\s*\+\s*(?:request\.getParameter|req\.getParameter)|(?:createElement|createTextNode|setAttribute)\s*\([^)]*getParameter\s*\("#).unwrap(),
        severity: Severity::High,
        message: "XML injection in Java - user input directly embedded in XML construction without encoding",
    },
    // #476: IDOR
    SecurityPattern {
        name: "java_idor",
        regex: Regex::new(r#"(?i)(?:findById|getById|load|get)\s*\(\s*(?:Integer|Long|UUID)?\s*\.?\s*(?:parse\w*)?\s*\(\s*request\.getParameter"#).unwrap(),
        severity: Severity::High,
        message: "Potential IDOR in Java - database lookup using user-supplied ID without authorization check",
    },
    SecurityPattern {
        name: "java_idor_path_variable",
        regex: Regex::new(r#"(?i)@(?:PathVariable|RequestParam)\s+(?:Long|Integer|String|UUID)\s+\w*[iI]d\b"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential IDOR in Java - user-supplied ID in path/request parameter; ensure authorization check exists",
    },
    // #484: Weak authentication
    SecurityPattern {
        name: "java_weak_auth_basic",
        regex: Regex::new(r#"(?i)(?:getHeader\s*\(\s*["']Authorization["']\s*\).*?(?:Base64|decode)|BasicAuth)"#).unwrap(),
        severity: Severity::Medium,
        message: "Weak authentication in Java - Basic authentication with Base64 decoding (not encryption)",
    },
    SecurityPattern {
        name: "java_weak_auth_equals",
        regex: Regex::new(r#"(?i)(?:password|token|secret)\s*\.\s*equals\s*\("#).unwrap(),
        severity: Severity::Medium,
        message: "Weak authentication in Java - string comparison for credentials (use constant-time comparison)",
    },
    // #477: Buffer overflow
    SecurityPattern {
        name: "java_buffer_overflow",
        regex: Regex::new(r#"(?i)(?:System\.arraycopy|ByteBuffer\.(?:allocate|wrap))\s*\([^)]*getParameter|(?:Unsafe)\s*\.\s*(?:putByte|copyMemory|allocateMemory)"#).unwrap(),
        severity: Severity::High,
        message: "Potential buffer overflow in Java - unsafe memory/buffer operation with user input or Unsafe API usage",
    },
    // #479: Integer overflow
    SecurityPattern {
        name: "java_integer_overflow",
        regex: Regex::new(r#"(?i)(?:Integer|Long)\s*\.\s*parse(?:Int|Long)\s*\(\s*(?:request\.getParameter|req\.getParameter)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential integer overflow in Java - parsing user input without range validation",
    },
    SecurityPattern {
        name: "java_integer_overflow_cast",
        regex: Regex::new(r#"(?i)\(\s*(?:int|short|byte)\s*\)\s*(?:Long\.parseLong|Integer\.parseInt)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential integer overflow in Java - narrowing cast of parsed numeric value",
    },
    // #490: Memory/Resource leak
    SecurityPattern {
        name: "java_resource_leak",
        regex: Regex::new(r#"(?i)(?:new\s+(?:FileInputStream|FileOutputStream|BufferedReader|Connection|Socket|ServerSocket|DatagramSocket))\s*\([^)]*\)\s*;"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential resource leak in Java - closeable resource not in try-with-resources block",
    },
    // #491: Null pointer dereference
    SecurityPattern {
        name: "java_null_deref",
        regex: Regex::new(r#"(?i)request\.getParameter\s*\([^)]*\)\s*\.\s*(?:equals|length|trim|split|charAt|substring|toLowerCase|toUpperCase)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential null pointer dereference in Java - calling method on getParameter() which may return null",
    },
    // #493: Uncontrolled recursion
    SecurityPattern {
        name: "java_uncontrolled_recursion",
        regex: Regex::new(r#"(?i)(?:return\s+\w+\s*\(|this\s*\.\s*\w+\s*\().*//\s*(?:recursive|recurse)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential uncontrolled recursion in Java - recursive method call without visible depth limit",
    },
    // #478: Race condition
    SecurityPattern {
        name: "java_race_condition",
        regex: Regex::new(r#"(?i)static\s+(?:(?:private|public|protected)\s+)?(?:int|long|boolean|String|Map|List|Set|HashMap|ArrayList)\s+\w+\s*[=;]"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential race condition in Java Servlet - mutable static field (servlets are shared across threads)",
    },
    // #492: Deadlock
    SecurityPattern {
        name: "java_deadlock",
        regex: Regex::new(r#"(?i)synchronized\s*\([^)]+\)\s*\{[^}]*synchronized\s*\("#).unwrap(),
        severity: Severity::High,
        message: "Potential deadlock in Java - nested synchronized blocks detected",
    },
    // #481: Insecure randomness
    SecurityPattern {
        name: "java_insecure_random",
        regex: Regex::new(r#"(?i)new\s+(?:java\.util\.)?Random\s*\(\s*\)|Math\s*\.\s*random\s*\(\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Insecure randomness in Java - java.util.Random/Math.random() is not cryptographically secure; use SecureRandom",
    },
    SecurityPattern {
        name: "java_insecure_random_seed",
        regex: Regex::new(r#"(?i)new\s+Random\s*\(\s*(?:System\.currentTimeMillis|System\.nanoTime|0|1|42)\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Insecure randomness in Java - Random seeded with predictable value",
    },
    // #482: Weak cryptography
    SecurityPattern {
        name: "java_weak_crypto",
        regex: Regex::new(r#"(?i)Cipher\s*\.\s*getInstance\s*\(\s*["'](?:DES|RC2|RC4|Blowfish|DESede|AES/ECB)["']"#).unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in Java - using deprecated/insecure cipher algorithm (DES/RC2/RC4/ECB mode)",
    },
    SecurityPattern {
        name: "java_weak_hash",
        regex: Regex::new(r#"(?i)MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']"#).unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in Java - using deprecated hash algorithm (MD5/SHA-1)",
    },
    // #485: Insecure file permissions
    SecurityPattern {
        name: "java_insecure_file_perms",
        regex: Regex::new(r#"(?i)(?:PosixFilePermissions\s*\.\s*fromString\s*\(\s*["']rwxrwxrwx["']|(?:setReadable|setWritable|setExecutable)\s*\(\s*true\s*,\s*false\s*\))"#).unwrap(),
        severity: Severity::High,
        message: "Insecure file permissions in Java - world-readable/writable/executable file permissions",
    },
    SecurityPattern {
        name: "java_insecure_temp_file",
        regex: Regex::new(r#"(?i)File\s*\.\s*createTempFile\s*\("#).unwrap(),
        severity: Severity::Medium,
        message: "Insecure file permissions in Java - File.createTempFile() may have predictable name; use Files.createTempFile()",
    },
    // #486: Unrestricted file upload
    SecurityPattern {
        name: "java_unrestricted_upload",
        regex: Regex::new(r#"(?i)(?:@MultipartConfig|getPart\s*\(|getParts\s*\(|MultipartFile|CommonsMultipartFile)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential unrestricted file upload in Java - ensure file type/size validation and secure storage path",
    },
    SecurityPattern {
        name: "java_unrestricted_upload_write",
        regex: Regex::new(r#"(?i)(?:part|file|upload)\s*\.\s*(?:write|transferTo)\s*\([^)]*getParameter"#).unwrap(),
        severity: Severity::High,
        message: "Unrestricted file upload in Java - uploaded file written to user-controlled path",
    },
    // #480: Unsafe reflection
    SecurityPattern {
        name: "java_unsafe_reflection",
        regex: Regex::new(r#"(?i)Class\s*\.\s*forName\s*\([^)]*getParameter\s*\(|\.newInstance\s*\(\s*\).*getParameter|(?:getMethod|getDeclaredMethod)\s*\([^)]*getParameter"#).unwrap(),
        severity: Severity::Critical,
        message: "Unsafe reflection in Java - user input used to load class or invoke method via reflection",
    },
    SecurityPattern {
        name: "java_unsafe_reflection_invoke",
        regex: Regex::new(r#"(?i)(?:Method|Constructor)\s*\.\s*invoke\s*\([^)]*getParameter"#).unwrap(),
        severity: Severity::Critical,
        message: "Unsafe reflection in Java - user input in reflective method invocation",
    },
    // #483: Improper error handling
    SecurityPattern {
        name: "java_improper_error_handling",
        regex: Regex::new(r#"(?i)catch\s*\(\s*(?:Exception|Throwable|RuntimeException)\s+\w+\s*\)\s*\{\s*\}"#).unwrap(),
        severity: Severity::Medium,
        message: "Improper error handling in Java - empty catch block swallows exception silently",
    },
    SecurityPattern {
        name: "java_stacktrace_exposure",
        regex: Regex::new(r#"(?i)(?:printStackTrace\s*\(\s*\)|getWriter\s*\(\s*\)\s*\.\s*(?:print|println)\s*\([^)]*(?:getMessage|getStackTrace|toString)\s*\(\s*\))"#).unwrap(),
        severity: Severity::Medium,
        message: "Improper error handling in Java - stack trace/error details exposed to user response",
    },
    // #495: HTTP request smuggling
    SecurityPattern {
        name: "java_http_smuggling",
        regex: Regex::new(r#"(?i)(?:getHeader\s*\(\s*["'](?:Transfer-Encoding|Content-Length)["']\s*\).*getHeader\s*\(\s*["'](?:Content-Length|Transfer-Encoding)["'])"#).unwrap(),
        severity: Severity::High,
        message: "Potential HTTP request smuggling in Java - both Transfer-Encoding and Content-Length headers processed",
    },
    SecurityPattern {
        name: "java_http_smuggling_forward",
        regex: Regex::new(r#"(?i)(?:setHeader|addHeader)\s*\(\s*["']Transfer-Encoding["']\s*,\s*["']chunked["']"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential HTTP request smuggling in Java - manually setting Transfer-Encoding header",
    },

    // Go/net/http vulnerability patterns (#439-#454)

    // #439: SQL injection in Go via fmt.Sprintf
    SecurityPattern {
        name: "go_sql_injection_sprintf",
        regex: Regex::new(r#"(?i)fmt\.Sprintf\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)[^"']*["']"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Go - fmt.Sprintf with user input in SQL query",
    },
    SecurityPattern {
        name: "go_sql_injection_concat",
        regex: Regex::new(r#"(?i)(?:\.Query|\.Exec|\.QueryRow)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+"#).unwrap(),
        severity: Severity::High,
        message: "Potential SQL injection in Go - string concatenation in SQL query",
    },

    // #440: XSS in Go via fmt.Fprintf
    SecurityPattern {
        name: "go_xss_fprintf",
        regex: Regex::new(r#"fmt\.Fprintf\s*\(\s*w\s*,"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential XSS in Go - fmt.Fprintf writing user input to HTTP response without escaping",
    },
    SecurityPattern {
        name: "go_xss_write_html",
        regex: Regex::new(r#"(?i)w\.Write\s*\(\s*\[\]byte\s*\(\s*["'][^"']*<[^"']*["']\s*\+"#).unwrap(),
        severity: Severity::High,
        message: "Potential XSS in Go - writing HTML with concatenated user input to response",
    },

    // #441: Path traversal in Go
    SecurityPattern {
        name: "go_path_traversal_readfile",
        regex: Regex::new(r"(?:ioutil\.ReadFile|os\.ReadFile|os\.Open)\s*\(\s*(?:r\.(?:URL\.Query|FormValue|Form\.Get)|filepath\.Join\s*\([^)]*r\.)").unwrap(),
        severity: Severity::High,
        message: "Potential path traversal in Go - file operation with user-supplied path",
    },
    SecurityPattern {
        name: "go_path_traversal_http",
        regex: Regex::new(r"(?:ioutil\.ReadFile|os\.ReadFile|os\.Open)\s*\(\s*(?:[a-zA-Z_][a-zA-Z0-9_]*\s*\+|fmt\.Sprintf)").unwrap(),
        severity: Severity::Medium,
        message: "Potential path traversal in Go - file read with dynamic path construction",
    },

    // #442: SSRF in Go
    SecurityPattern {
        name: "go_ssrf_http_get",
        regex: Regex::new(r"http\.(?:Get|Post|PostForm|Head)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)").unwrap(),
        severity: Severity::Medium,
        message: "Potential SSRF in Go - HTTP request with variable URL (verify not user-controlled)",
    },
    SecurityPattern {
        name: "go_ssrf_http_get_direct",
        regex: Regex::new(r"http\.(?:Get|Post|PostForm|Head)\s*\(\s*(?:r\.(?:URL\.Query|FormValue|Form\.Get)|fmt\.Sprintf)").unwrap(),
        severity: Severity::High,
        message: "Potential SSRF in Go - HTTP request with user-supplied URL",
    },
    SecurityPattern {
        name: "go_ssrf_client",
        regex: Regex::new(r"(?:client\.(?:Get|Do|Post)|http\.NewRequest)\s*\([^)]*(?:r\.(?:URL\.Query|FormValue)|fmt\.Sprintf)").unwrap(),
        severity: Severity::High,
        message: "Potential SSRF in Go - HTTP client request with user-controlled URL",
    },

    // #443: XXE in Go
    SecurityPattern {
        name: "go_xxe_xml_unmarshal",
        regex: Regex::new(r"xml\.(?:Unmarshal|NewDecoder)\s*\(").unwrap(),
        severity: Severity::Medium,
        message: "Potential XXE in Go - XML parsing of untrusted input without entity restriction",
    },

    // #444: Open redirect in Go
    SecurityPattern {
        name: "go_open_redirect",
        regex: Regex::new(r"http\.Redirect\s*\(\s*w\s*,\s*r\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,").unwrap(),
        severity: Severity::Medium,
        message: "Potential open redirect in Go - http.Redirect with variable URL (verify not user-controlled)",
    },
    SecurityPattern {
        name: "go_open_redirect_direct",
        regex: Regex::new(r"http\.Redirect\s*\(\s*w\s*,\s*r\s*,\s*(?:r\.(?:URL\.Query|FormValue|Form\.Get)|fmt\.Sprintf)").unwrap(),
        severity: Severity::High,
        message: "Potential open redirect in Go - http.Redirect with user-supplied URL",
    },

    // #445: Template injection in Go
    SecurityPattern {
        name: "go_template_injection",
        regex: Regex::new(r"\.Parse\s*\(\s*(?:r\.(?:FormValue|URL\.Query)|[a-zA-Z_][a-zA-Z0-9_]*\s*\+)").unwrap(),
        severity: Severity::High,
        message: "Potential template injection in Go - template.Parse with user input",
    },
    SecurityPattern {
        name: "go_template_injection_sprintf",
        regex: Regex::new(r"\.Parse\s*\(\s*fmt\.Sprintf").unwrap(),
        severity: Severity::High,
        message: "Potential template injection in Go - template.Parse with fmt.Sprintf user input",
    },

    // #446: IDOR in Go
    SecurityPattern {
        name: "go_idor_direct_access",
        regex: Regex::new(r#"(?:db\.Query|db\.QueryRow|db\.Exec)\s*\(\s*["'][^"']*(?:WHERE|where)[^"']*["']\s*,"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential IDOR in Go - direct database query with user-supplied ID without authorization check",
    },

    // #447: Integer overflow in Go
    SecurityPattern {
        name: "go_integer_overflow",
        regex: Regex::new(r"(?:strconv\.Atoi|strconv\.ParseInt)\s*\(\s*(?:r\.(?:URL\.Query|FormValue|Form\.Get))").unwrap(),
        severity: Severity::Medium,
        message: "Potential integer overflow in Go - unchecked integer conversion from user input",
    },
    SecurityPattern {
        name: "go_integer_overflow_arithmetic",
        regex: Regex::new(r"(?:strconv\.Atoi|strconv\.ParseInt)[^}]*(?:\*|\+)\s*[a-zA-Z_][a-zA-Z0-9_]*").unwrap(),
        severity: Severity::Medium,
        message: "Potential integer overflow in Go - arithmetic on user-supplied integer without bounds checking",
    },

    // #448: Format string in Go
    SecurityPattern {
        name: "go_format_string",
        regex: Regex::new(r"fmt\.Fprintf\s*\(\s*w\s*,\s*(?:r\.(?:FormValue|URL\.Query)|[a-zA-Z_][a-zA-Z0-9_]*\s*\))").unwrap(),
        severity: Severity::High,
        message: "Potential format string vulnerability in Go - user input as format string in fmt.Fprintf",
    },

    // #449: Weak cryptography in Go
    SecurityPattern {
        name: "go_weak_crypto_md5",
        regex: Regex::new(r"(?:md5\.(?:New|Sum)|crypto/md5)").unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in Go - MD5 should not be used for password hashing or security",
    },
    SecurityPattern {
        name: "go_weak_crypto_sha1",
        regex: Regex::new(r"(?:sha1\.(?:New|Sum)|crypto/sha1)").unwrap(),
        severity: Severity::Medium,
        message: "Weak cryptography in Go - SHA1 is deprecated for security purposes",
    },

    // #450: Missing rate limiting in Go
    SecurityPattern {
        name: "go_missing_rate_limit",
        regex: Regex::new(r"http\.(?:HandleFunc|Handle)\s*\(\s*[^)]*\)\s*$").unwrap(),
        severity: Severity::Low,
        message: "Potential missing rate limiting in Go - HTTP endpoint without rate limiter middleware",
    },

    // #451: Missing CSP in Go
    SecurityPattern {
        name: "go_missing_csp_html",
        regex: Regex::new(r#"(?:w\.Header\(\)\.Set|Header\.Set)\s*\(\s*["']Content-Type["']\s*,\s*["']text/html["']"#).unwrap(),
        severity: Severity::Low,
        message: "Potential missing CSP in Go - HTML response without Content-Security-Policy header",
    },

    // #452: Weak authentication / hardcoded credentials in Go
    SecurityPattern {
        name: "go_hardcoded_credentials",
        regex: Regex::new(r#"(?i)(?:password|passwd|secret|credential)\s*(?::=|=)\s*["'][^"']{4,}["']"#).unwrap(),
        severity: Severity::High,
        message: "Hardcoded credentials in Go - password/secret should not be hardcoded",
    },

    // #453: Unrestricted file upload in Go
    SecurityPattern {
        name: "go_unrestricted_upload",
        regex: Regex::new(r"r\.FormFile\s*\(\s*[^)]*\)").unwrap(),
        severity: Severity::Medium,
        message: "Potential unrestricted file upload in Go - file upload without content type or size validation",
    },

    // #454: LDAP injection in Go
    SecurityPattern {
        name: "go_ldap_injection",
        regex: Regex::new(r#"fmt\.Sprintf\s*\(\s*["'][^"']*(?:uid=|cn=|ou=|dc=|dn=|\([\w]+=)[^"']*["']"#).unwrap(),
        severity: Severity::High,
        message: "Potential LDAP injection in Go - fmt.Sprintf with user input in LDAP query",
    },

    // Additional Go vulnerability patterns
    // #582: Unsafe deserialization
    SecurityPattern {
        name: "go_unsafe_deserialization",
        regex: Regex::new(r#"gob\.Decode|encoding\/binary\.Read\([^)]*io\.Reader[^)]*\)"#).unwrap(),
        severity: Severity::High,
        message: "Unsafe deserialization in Go - gob.Decode or binary.Read with untrusted data",
    },

    // #584: Unsafe reflection
    SecurityPattern {
        name: "go_unsafe_reflection",
        regex: Regex::new(r#"reflect\.ValueOf\([^)]*\)\.Elem\(\)\.FieldByName\("#).unwrap(),
        severity: Severity::High,
        message: "Unsafe reflection in Go - reflect.ValueOf with user input accessing struct fields",
    },

    // #585: Header injection
    SecurityPattern {
        name: "go_header_injection",
        regex: Regex::new(r#"Header\.Set\s*\([^)]*(?:req\.|r\.|user|input)"#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Go - user input in Header.Set without validation",
    },

    // Go/Fiber specific patterns
    // Header injection in Fiber
    SecurityPattern {
        name: "go_fiber_header_injection",
        regex: Regex::new(r#"Header\.Set\([^)]*c\.(Query|FormValue|Params)"#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Fiber - user input in Header.Set without validation",
    },

    // Unvalidated redirect in Fiber
    SecurityPattern {
        name: "go_fiber_redirect",
        regex: Regex::new(r#"c\.(Redirect|RedirectTo)\s*\(\s*\d+\s*,\s*c\.(Query|FormValue|Params)"#).unwrap(),
        severity: Severity::Medium,
        message: "Unvalidated redirect in Fiber - c.Redirect with user-controlled URL",
    },

    // #586: Log injection
    SecurityPattern {
        name: "go_log_injection",
        regex: Regex::new(r#"(?:log\.|fmt\.Print|print|println)\s*\([^)]*(?:req\.|r\.|user|input)"#).unwrap(),
        severity: Severity::Medium,
        message: "Log injection in Go - user input in logging without sanitization",
    },

    // #587: ReDoS (Regex DoS)
    SecurityPattern {
        name: "go_redos",
        regex: Regex::new(r#"regexp\.Compile\([^)]*\+[^)]*\)|regexp\.MustCompile\([^)]*\+[^)]*\)"#).unwrap(),
        severity: Severity::High,
        message: "ReDoS in Go - user-controlled input in regexp.Compile can cause denial of service",
    },

    // #588: Unsafe JSON unmarshal
    SecurityPattern {
        name: "go_json_unmarshal_any",
        regex: Regex::new(r#"json\.Unmarshal\([^,]*,\s*&[a-zA-Z_][a-zA-Z0-9_]*\{"#).unwrap(),
        severity: Severity::Medium,
        message: "Unsafe JSON unmarshal in Go - Unmarshal into interface{} can cause type confusion",
    },

    // #590: Buffer overflow (unsafe pointer)
    SecurityPattern {
        name: "go_buffer_overflow",
        regex: Regex::new(r#"unsafe\.Pointer|unsafe\.Addr|unsafe\.SliceData"#).unwrap(),
        severity: Severity::High,
        message: "Buffer overflow risk in Go - unsafe pointer operations require careful bounds checking",
    },

    // #591: Insecure random
    SecurityPattern {
        name: "go_insecure_random",
        regex: Regex::new(r#"math\/rand\.Intn|math\/rand\.Int63n|rand\.Intn|rand\.Int63n"#).unwrap(),
        severity: Severity::Medium,
        message: "Insecure random in Go - math/rand is not cryptographically secure; use crypto/rand",
    },

    // TypeScript/Express vulnerability patterns (#500-#526)

    // #500: XSS — user input reflected in HTML via res.send() with template literals
    SecurityPattern {
        name: "ts_express_xss_res_send",
        regex: Regex::new(r#"res\.send\s*\(\s*`[^`]*\$\{[^}]*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "XSS in Express - user input from req.body/query/params reflected in res.send() template literal",
    },
    SecurityPattern {
        name: "ts_express_xss_res_send_concat",
        regex: Regex::new(r#"res\.send\s*\(\s*["']<[^"']*["']\s*\+\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "XSS in Express - user input concatenated into HTML string in res.send()",
    },
    SecurityPattern {
        name: "ts_express_xss_res_send_html",
        regex: Regex::new(r#"res\.send\s*\(\s*`\s*<(?:html|div|span|p|h[1-6]|script|img|a|form|table|body)[^`]*\$\{"#).unwrap(),
        severity: Severity::High,
        message: "XSS in Express - HTML template literal with interpolated values in res.send()",
    },

    // #501: Path traversal — path.join with user input + fs.readFile
    SecurityPattern {
        name: "ts_express_path_traversal_join",
        regex: Regex::new(r#"path\.join\s*\([^)]*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Express - user input in path.join() without sanitization",
    },
    SecurityPattern {
        name: "ts_express_path_traversal_fs",
        regex: Regex::new(r#"fs\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|access|accessSync|stat|statSync)\s*\([^)]*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Express - user input directly in fs file operation",
    },

    // #502: SSRF — axios.get/fetch with user-controlled URL
    SecurityPattern {
        name: "ts_express_ssrf_axios",
        regex: Regex::new(r#"axios\.(get|post|put|delete|patch|head|request)\s*\(\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Express - user-controlled URL passed to axios without validation",
    },
    SecurityPattern {
        name: "ts_express_ssrf_fetch",
        regex: Regex::new(r#"fetch\s*\(\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Express - user-controlled URL passed to fetch() without validation",
    },
    SecurityPattern {
        name: "ts_express_ssrf_http",
        regex: Regex::new(r#"(?:http|https)\.(?:get|request)\s*\(\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Express - user-controlled URL passed to http.get/request without validation",
    },

    // #503/#518: Open redirect / Unvalidated redirect — res.redirect with user input
    SecurityPattern {
        name: "ts_express_open_redirect",
        regex: Regex::new(r#"res\.redirect\s*\(\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::Medium,
        message: "Open redirect in Express - user input in res.redirect() without validation",
    },
    SecurityPattern {
        name: "ts_express_open_redirect_var",
        regex: Regex::new(r#"res\.redirect\s*\(\s*(?:url|redirect|returnUrl|next|returnTo|destination|goto|target|forward|redir)\s*\)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential open redirect in Express - variable in res.redirect(); ensure URL is validated",
    },

    // #504: Insecure deserialization — JSON.parse controlling auth/logic
    SecurityPattern {
        name: "ts_express_insecure_deserialization",
        regex: Regex::new(r#"JSON\.parse\s*\(\s*req\.(body|query|params|headers)"#).unwrap(),
        severity: Severity::Medium,
        message: "Insecure deserialization in Express - JSON.parse on raw user input may control auth/logic flow",
    },

    // #505/#526: Template injection / SSTI — user input in template rendering
    SecurityPattern {
        name: "ts_express_ssti_render",
        regex: Regex::new(r#"res\.render\s*\(\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::Critical,
        message: "Server-side template injection in Express - user input controls template name in res.render()",
    },
    SecurityPattern {
        name: "ts_express_ssti_template_literal",
        regex: Regex::new(r#"res\.send\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`\s*\)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential template injection in Express - template literal with interpolated values sent as HTML",
    },

    // EJS template injection
    SecurityPattern {
        name: "ts_express_ejs_ssti",
        regex: Regex::new(r#"ejs\.render\s*\([^)]*request|res\.render\s*\([^)]*request\."#).unwrap(),
        severity: Severity::Critical,
        message: "EJS template injection in Express - render with user-controlled template or data",
    },

    // Math expression injection
    SecurityPattern {
        name: "ts_express_math_injection",
        regex: Regex::new(r#"math\.(evaluate|compile)\s*\([^)]*request\."#).unwrap(),
        severity: Severity::High,
        message: "Expression language injection in Express - math.evaluate/compile with user input",
    },

    // #506: Mass assignment — req.body spread/assigned to object with privileged fields
    SecurityPattern {
        name: "ts_express_mass_assignment_spread",
        regex: Regex::new(r#"\.\.\.\s*req\.body"#).unwrap(),
        severity: Severity::High,
        message: "Mass assignment in Express - spreading req.body may include privileged fields (role, isAdmin, etc.)",
    },
    SecurityPattern {
        name: "ts_express_mass_assignment_assign",
        regex: Regex::new(r#"Object\.assign\s*\([^,]*,\s*req\.body"#).unwrap(),
        severity: Severity::High,
        message: "Mass assignment in Express - Object.assign with req.body may include privileged fields",
    },
    SecurityPattern {
        name: "ts_express_mass_assignment_create",
        regex: Regex::new(r#"\.create\s*\(\s*req\.body\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Mass assignment in Express - passing req.body directly to .create() without field filtering",
    },
    SecurityPattern {
        name: "ts_express_mass_assignment_typed",
        regex: Regex::new(r#"(?:const|let|var)\s+\w+\s*(?::\s*\w+)?\s*=\s*req\.body\s*(?:as\s+\w+)?\s*;"#).unwrap(),
        severity: Severity::Medium,
        message: "Mass assignment in Express - req.body cast to typed object without field validation",
    },

    // #507: IDOR — /user/:id endpoint without auth check
    SecurityPattern {
        name: "ts_express_idor_params_id",
        regex: Regex::new(r#"req\.params\.(?:id|userId|user_id)\b"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential IDOR in Express - direct use of req.params.id; ensure authorization check exists",
    },
    SecurityPattern {
        name: "ts_express_idor_findbyid",
        regex: Regex::new(r#"\.findBy(?:Id|Pk)\s*\(\s*req\.params"#).unwrap(),
        severity: Severity::High,
        message: "Potential IDOR in Express - database lookup using req.params without authorization check",
    },

    // #508: Buffer overflow — writing beyond Buffer.alloc bounds
    SecurityPattern {
        name: "ts_express_buffer_overflow",
        regex: Regex::new(r#"Buffer\.alloc\s*\(\s*\d+\s*\)[^;]*\.write\s*\("#).unwrap(),
        severity: Severity::High,
        message: "Potential buffer overflow in Node.js - writing to Buffer.alloc() without bounds checking",
    },
    SecurityPattern {
        name: "ts_express_buffer_overflow_copy",
        regex: Regex::new(r#"\.copy\s*\(\s*Buffer\.alloc\s*\(\s*\d+\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Potential buffer overflow in Node.js - copy to fixed-size buffer without bounds checking",
    },

    // #509: Race condition — non-atomic check-then-act
    SecurityPattern {
        name: "ts_express_race_condition",
        regex: Regex::new(r#"(?:if\s*\([^)]*(?:balance|count|stock|quantity|amount|credits|seats|inventory)[^)]*\)[\s\S]*?setTimeout)"#).unwrap(),
        severity: Severity::High,
        message: "Race condition in Express - non-atomic check-then-act with setTimeout; use transactions or locks",
    },

    // #510: Prototype pollution — Object.assign to prototype
    SecurityPattern {
        name: "ts_express_prototype_pollution",
        regex: Regex::new(r#"Object\.assign\s*\(\s*\w+\.prototype\s*,\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::Critical,
        message: "Prototype pollution in Express - Object.assign to prototype with user input",
    },
    SecurityPattern {
        name: "ts_express_prototype_pollution_bracket",
        regex: Regex::new(r#"\[req\.(body|query|params)\.\w+\]\s*="#).unwrap(),
        severity: Severity::High,
        message: "Potential prototype pollution in Express - dynamic property assignment from user input",
    },

    // #511: Type juggling — weak comparison with user input
    SecurityPattern {
        name: "ts_express_type_juggling",
        regex: Regex::new(r#"(?:password|token|secret|key|code|pin|otp)\s*==\s*(?:req\.|user\.|.*\.toString\(\))"#).unwrap(),
        severity: Severity::High,
        message: "Type juggling in Express - loose equality (==) for security comparison; use strict equality (===)",
    },
    SecurityPattern {
        name: "ts_express_type_juggling_reverse",
        regex: Regex::new(r#"req\.(body|query|params)\.\w+\s*==\s*(?:user|account|stored)"#).unwrap(),
        severity: Severity::High,
        message: "Type juggling in Express - loose equality (==) comparing user input to stored value",
    },

    // #512: Insecure randomness — Math.random() for tokens
    SecurityPattern {
        name: "ts_express_insecure_random",
        regex: Regex::new(r#"Math\.random\s*\(\s*\).*(?:token|secret|key|session|csrf|nonce|salt|password|otp|code|id)"#).unwrap(),
        severity: Severity::High,
        message: "Insecure randomness in Node.js - Math.random() used for security token; use crypto.randomBytes()",
    },
    SecurityPattern {
        name: "ts_express_insecure_random_reverse",
        regex: Regex::new(r#"(?:token|secret|key|session|csrf|nonce|salt|password|otp|code)\s*=.*Math\.random\s*\(\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Insecure randomness in Node.js - Math.random() assigned to security-sensitive variable",
    },

    // #513: Weak cryptography — MD5/SHA1 for password hashing
    SecurityPattern {
        name: "ts_express_weak_crypto_md5",
        regex: Regex::new(r#"crypto\.createHash\s*\(\s*['"]md5['"]\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in Node.js - MD5 used for hashing; use bcrypt/scrypt/argon2 for passwords",
    },
    SecurityPattern {
        name: "ts_express_weak_crypto_sha1",
        regex: Regex::new(r#"crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)"#).unwrap(),
        severity: Severity::Medium,
        message: "Weak cryptography in Node.js - SHA1 is deprecated; use SHA-256+ or bcrypt for passwords",
    },

    // #514: Missing rate limiting — no rate limiter on endpoints
    SecurityPattern {
        name: "ts_express_no_rate_limit_login",
        regex: Regex::new(r#"(?:app|router)\.(post|all)\s*\(\s*['"](?:/login|/auth|/signin|/api/auth|/api/login)['"]"#).unwrap(),
        severity: Severity::Medium,
        message: "Missing rate limiting in Express - auth endpoint without rate limiter; use express-rate-limit",
    },

    // #515: Missing CSP — Express serving HTML without Content-Security-Policy
    SecurityPattern {
        name: "ts_express_no_csp",
        regex: Regex::new(r#"res\.send\s*\(\s*[`'"]\s*<!DOCTYPE|res\.send\s*\(\s*[`'"]\s*<html"#).unwrap(),
        severity: Severity::Medium,
        message: "Missing CSP in Express - serving HTML without Content-Security-Policy header; use helmet",
    },

    // #516: Weak authentication — plaintext password comparison, hardcoded credentials
    SecurityPattern {
        name: "ts_express_plaintext_password",
        regex: Regex::new(r#"(?:password|passwd|pwd)\s*===?\s*(?:req\.body|user|stored|db)\.\w+"#).unwrap(),
        severity: Severity::High,
        message: "Weak authentication in Express - plaintext password comparison; use bcrypt.compare()",
    },
    SecurityPattern {
        name: "ts_express_hardcoded_creds",
        regex: Regex::new(r#"(?:password|passwd|pwd)\s*===?\s*['"][^'"]{4,}['"]\s*(?:\)|&&|\|\|)"#).unwrap(),
        severity: Severity::Critical,
        message: "Weak authentication in Express - hardcoded password in comparison",
    },

    // #517: Unrestricted file upload — multer without file type/size validation
    SecurityPattern {
        name: "ts_express_unrestricted_upload",
        regex: Regex::new(r#"multer\s*\(\s*\{?\s*(?:dest|storage)\s*:"#).unwrap(),
        severity: Severity::Medium,
        message: "Unrestricted file upload in Express - multer without fileFilter or limits configuration",
    },
    SecurityPattern {
        name: "ts_express_unrestricted_upload_any",
        regex: Regex::new(r#"(?:upload|multer)\s*\.\s*any\s*\(\s*\)"#).unwrap(),
        severity: Severity::High,
        message: "Unrestricted file upload in Express - multer.any() accepts all files without restriction",
    },

    // #519: XML injection — parseString with user input
    SecurityPattern {
        name: "ts_express_xml_injection",
        regex: Regex::new(r#"parseString\s*\(\s*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "XML injection in Express - user input parsed as XML without sanitization; risk of XXE",
    },
    SecurityPattern {
        name: "ts_express_xml_injection_parser",
        regex: Regex::new(r#"(?:xml2js|libxmljs|fast-xml-parser|xmldom).*(?:parse|parseString)\s*\(\s*req\."#).unwrap(),
        severity: Severity::High,
        message: "XML injection in Express - user input in XML parser without sanitization",
    },

    // #520: LDAP injection — user input in LDAP filter string
    SecurityPattern {
        name: "ts_express_ldap_injection",
        regex: Regex::new(r#"(?:search|bind)\s*\([^)]*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "LDAP injection in Express - user input in LDAP operation without sanitization",
    },
    SecurityPattern {
        name: "ts_express_ldap_injection_filter",
        regex: Regex::new(r#"`\s*\([^`]*=\s*\$\{[^}]*req\.(body|query|params)"#).unwrap(),
        severity: Severity::Critical,
        message: "LDAP injection in Express - user input interpolated into LDAP filter string",
    },

    // #521: Memory leak — unbounded global array push per request
    SecurityPattern {
        name: "ts_express_memory_leak_global",
        regex: Regex::new(r#"(?:const|let|var)\s+\w+\s*(?::\s*\w+(?:\[\])?)?\s*=\s*\[\s*\]\s*;[\s\S]*?(?:app|router)\.\w+\s*\([\s\S]*?\w+\.push\s*\("#).unwrap(),
        severity: Severity::High,
        message: "Memory leak in Express - unbounded array grows with each request; implement cleanup or limits",
    },

    // #522: Deadlock — two DB connections acquiring locks in opposite order
    SecurityPattern {
        name: "ts_express_deadlock",
        regex: Regex::new(r#"(?:BEGIN|LOCK TABLE|SELECT.*FOR UPDATE)[\s\S]*?(?:BEGIN|LOCK TABLE|SELECT.*FOR UPDATE)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential deadlock - multiple lock acquisitions detected; ensure consistent ordering",
    },

    // #523: Uncontrolled recursion — recursive function without bounds
    SecurityPattern {
        name: "ts_express_uncontrolled_recursion",
        regex: Regex::new(r#"(?:function\s+\w+|const\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*(?::\s*\w+)?\s*=>)\s*[^;]*(?:arguments\.callee|this\.\w+)\s*\("#).unwrap(),
        severity: Severity::Medium,
        message: "Uncontrolled recursion - recursive function call without visible depth limit",
    },

    // #524: CRLF injection — user input in res.download/res.setHeader
    SecurityPattern {
        name: "ts_express_crlf_injection",
        regex: Regex::new(r#"res\.(?:download|attachment|setHeader|set|header)\s*\([^)]*req\.(body|query|params)"#).unwrap(),
        severity: Severity::High,
        message: "CRLF injection in Express - user input in response header/download filename",
    },

    // #525: HTTP request smuggling — forwarding Content-Length/Transfer-Encoding
    SecurityPattern {
        name: "ts_express_http_smuggling",
        regex: Regex::new(r#"(?:req\.headers\s*\[\s*['"](?:content-length|transfer-encoding)['"]\s*\])"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential HTTP request smuggling in Express - forwarding Content-Length/Transfer-Encoding headers",
    },
    SecurityPattern {
        name: "ts_express_http_smuggling_forward",
        regex: Regex::new(r#"(?:setHeader|set)\s*\(\s*['"]Transfer-Encoding['"]\s*,\s*req\."#).unwrap(),
        severity: Severity::High,
        message: "HTTP request smuggling in Express - forwarding Transfer-Encoding header from client request",
    },

    // JavaScript/React/Next.js specific vulnerability patterns

    // JavaScript XSS - innerHTML/dangerouslySetInnerHTML
    SecurityPattern {
        name: "js_xss_innerHTML",
        regex: Regex::new(r"(?i)(?:innerHTML|outerHTML)\s*=\s*[^=]+").unwrap(),
        severity: Severity::High,
        message: "XSS in JavaScript - direct innerHTML/outerHTML assignment; use textContent or sanitize",
    },
    SecurityPattern {
        name: "js_xss_dangerously_set_inner_html",
        regex: Regex::new(r"(?i)dangerouslySetInnerHTML\s*=\s*\{").unwrap(),
        severity: Severity::High,
        message: "XSS in React - dangerouslySetInnerHTML without proper sanitization; use DOMPurify",
    },
    SecurityPattern {
        name: "js_xss_document_write",
        regex: Regex::new(r"(?i)document\.write\s*\(").unwrap(),
        severity: Severity::High,
        message: "XSS in JavaScript - document.write() is dangerous; use safe DOM methods",
    },
    SecurityPattern {
        name: "js_eval",
        regex: Regex::new(r"(?i)\beval\s*\(").unwrap(),
        severity: Severity::High,
        message: "Code injection in JavaScript - eval() executes arbitrary code; avoid if possible",
    },
    SecurityPattern {
        name: "js_functionConstructor",
        regex: Regex::new(r"(?i)new\s+Function\s*\(").unwrap(),
        severity: Severity::High,
        message: "Code injection in JavaScript - Function constructor is similar to eval",
    },
    SecurityPattern {
        name: "js_setTimeout_string",
        regex: Regex::new(r"(?i)setTimeout\s*\(\s*[']").unwrap(),
        severity: Severity::Medium,
        message: "Code injection risk in JavaScript - setTimeout with string argument; use function reference",
    },
    SecurityPattern {
        name: "js_setInterval_string",
        regex: Regex::new(r"(?i)setInterval\s*\(\s*[']").unwrap(),
        severity: Severity::Medium,
        message: "Code injection risk in JavaScript - setInterval with string argument; use function reference",
    },

    // JavaScript SQL injection
    SecurityPattern {
        name: "js_sql_injection_concat",
        regex: Regex::new(r#"(?i)(?:query|execute|all|run)\s*\(\s*['"]SELECT.*\+.*req\."#).unwrap(),
        severity: Severity::High,
        message: "SQL injection in JavaScript - user input concatenated in SQL query",
    },
    SecurityPattern {
        name: "js_sql_injection_template",
        regex: Regex::new(r#"(?i)(?:query|execute|all|run)\s*\(\s*`.*\$\{.*req\."#).unwrap(),
        severity: Severity::High,
        message: "SQL injection in JavaScript - template literal with user input in SQL query",
    },

    // JavaScript Command Injection
    SecurityPattern {
        name: "js_command_injection_exec",
        regex: Regex::new(r#"(?i)(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\+"#).unwrap(),
        severity: Severity::High,
        message: "Command injection in JavaScript - user input in command execution",
    },
    SecurityPattern {
        name: "js_command_injection_template",
        regex: Regex::new(r#"(?i)(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{"#).unwrap(),
        severity: Severity::High,
        message: "Command injection in JavaScript - template literal with user input in command",
    },

    // NoSQL injection in JS
    SecurityPattern {
        name: "js_nosql_injection",
        regex: Regex::new(r#"(?:db|collection)\.find\s*\(\s*request\.|db\.findOne\s*\(\s*\{[^}]*request\.|MongoClient\.connect\([^)]*request"#).unwrap(),
        severity: Severity::High,
        message: "NoSQL injection in JavaScript - MongoDB query with user input without sanitization",
    },

    // LDAP injection in JS
    SecurityPattern {
        name: "js_ldap_injection",
        regex: Regex::new(r#"(?:ldap|LDAP)\.[a-z_]+\([^)]*request\."#).unwrap(),
        severity: Severity::High,
        message: "LDAP injection in JavaScript - user input in LDAP query without sanitization",
    },

    // Header injection in JS
    SecurityPattern {
        name: "js_header_injection",
        regex: Regex::new(r#"res\.setHeader\s*\([^)]*request\.|response\.headers\[[^\]]*\]\s*=.*request\."#).unwrap(),
        severity: Severity::High,
        message: "Header injection in JavaScript - user input in response headers without validation",
    },

    // ReDoS in JS
    SecurityPattern {
        name: "js_redos",
        regex: Regex::new(r#"new\s+RegExp\s*\(\s*request\."#).unwrap(),
        severity: Severity::High,
        message: "ReDoS in JavaScript - user-controlled input in RegExp can cause denial of service",
    },

    // Insecure file upload in JS
    SecurityPattern {
        name: "js_insecure_upload",
        regex: Regex::new(r#"(?:writeFile|writeFileSync|createWriteStream)\s*\(\s*request\.|fs\.writeFile\([^)]*request\.files"#).unwrap(),
        severity: Severity::High,
        message: "Insecure file upload in JavaScript - user-controlled filename without validation",
    },

    // JavaScript Path Traversal
    SecurityPattern {
        name: "js_path_traversal",
        regex: Regex::new(r#"(?i)(?:readFile|readFileSync|writeFile|writeFileSync|open|readdir|stat)\s*\([^)]*\+[^)]*req\."#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in JavaScript - user input concatenated in file path",
    },

    // Nuxt.js/h3 specific patterns
    // SQL injection in Nuxt
    SecurityPattern {
        name: "js_nuxt_sql_injection",
        regex: Regex::new(r#"sqlite3\.[a-z_]+\([^)]*\$\{.*getQuery|db\.run\s*\(\s*`[^`]*\$\{"#).unwrap(),
        severity: Severity::High,
        message: "SQL injection in Nuxt/h3 - string interpolation in SQL query",
    },

    // Path traversal in Nuxt
    SecurityPattern {
        name: "js_nuxt_path_traversal",
        regex: Regex::new(r#"path\.join\([^)]*getQuery\(|join\([^)]*getQuery\("#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Nuxt/h3 - join with unsanitized user input from getQuery",
    },

    // SSRF in Nuxt
    SecurityPattern {
        name: "js_nuxt_ssrf",
        regex: Regex::new(r#"fetch\s*\([^)]*getQuery\(|fetch\s*\([^)]*await readBody\("#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Nuxt/h3 - fetch with user-controlled URL from getQuery",
    },

    // Template injection in Nuxt
    SecurityPattern {
        name: "js_nuxt_template_injection",
        regex: Regex::new(r#"Handlebars\.compile\s*\([^)]*await readBody\("#).unwrap(),
        severity: Severity::Critical,
        message: "Template injection in Nuxt/h3 - Handlebars.compile with user-supplied template",
    },

    // LDAP injection in Nuxt
    SecurityPattern {
        name: "js_nuxt_ldap_injection",
        regex: Regex::new(r#"ldap\.[a-z_]+\([^)]*getQuery\(|LDAP\([^)]*getQuery\("#).unwrap(),
        severity: Severity::High,
        message: "LDAP injection in Nuxt/h3 - user input in LDAP filter via getQuery",
    },

    // NoSQL injection in Nuxt
    SecurityPattern {
        name: "js_nuxt_nosql_injection",
        regex: Regex::new(r#"mongo|collection\.[a-z_]+\s*\([^)]*await readBody\("#).unwrap(),
        severity: Severity::High,
        message: "NoSQL injection in Nuxt/h3 - MongoDB filter from readBody without sanitization",
    },

    // Open redirect in Nuxt
    SecurityPattern {
        name: "js_nuxt_open_redirect",
        regex: Regex::new(r#"sendRedirect\s*\([^)]*getQuery\(|sendRedirect\s*\([^)]*await readBody\("#).unwrap(),
        severity: Severity::Medium,
        message: "Open redirect in Nuxt/h3 - sendRedirect with unvalidated URL from user input",
    },

    // Header injection in Nuxt
    SecurityPattern {
        name: "js_nuxt_header_injection",
        regex: Regex::new(r#"setHeader\s*\([^)]*getQuery\(|setHeader\s*\([^)]*getHeader\("#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Nuxt/h3 - setHeader with unsanitized user input",
    },

    // Prototype pollution in Nuxt
    SecurityPattern {
        name: "js_nuxt_prototype_pollution",
        regex: Regex::new(r#"Object\.assign\s*\([^)]*await readBody\("#).unwrap(),
        severity: Severity::Critical,
        message: "Prototype pollution in Nuxt/h3 - Object.assign with unsanitized readBody",
    },

    // JavaScript SSRF
    SecurityPattern {
        name: "js_ssrf_fetch",
        regex: Regex::new(r#"(?i)fetch\s*\(\s*[^,)]*\+[^,)]*req\."#).unwrap(),
        severity: Severity::High,
        message: "SSRF in JavaScript - user input in fetch URL",
    },
    SecurityPattern {
        name: "js_ssrf_axios",
        regex: Regex::new(r#"(?i)(?:axios|request|http)\.[a-z]+\s*\([^)]*\+[^)]*req\."#).unwrap(),
        severity: Severity::High,
        message: "SSRF in JavaScript - user input in HTTP request URL",
    },

    // JavaScript Path Traversal in Next.js API routes
    SecurityPattern {
        name: "js_nextjs_path_traversal",
        regex: Regex::new(r#"(?i)(?:fs\.(?:readFile|readFileSync|readdir)|path\.join)\s*\([^)]*req\.(?:query|body|params)"#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Next.js API route - user input in file system operation",
    },

    // JavaScript/Next.js Hardcoded secrets
    SecurityPattern {
        name: "js_hardcoded_api_key",
        regex: Regex::new(r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]"#).unwrap(),
        severity: Severity::Critical,
        message: "Hardcoded secret in JavaScript - API key or token in source code",
    },

    // JavaScript Insecure Randomness
    SecurityPattern {
        name: "js_insecure_random",
        regex: Regex::new(r"(?i)Math\.random\s*\(\s*\)").unwrap(),
        severity: Severity::Medium,
        message: "Insecure randomness in JavaScript - Math.random() is not cryptographically secure",
    },

    // JavaScript Weak Cryptography
    SecurityPattern {
        name: "js_weak_crypto_md5",
        regex: Regex::new(r"(?i)(?:createHash.*md5|crypto.*md5|md5\(|MD5\()").unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in JavaScript - MD5 is deprecated for security purposes; use SHA-256 or stronger",
    },
    SecurityPattern {
        name: "js_weak_crypto_des",
        regex: Regex::new(r"(?i)(?:createCipher.*des|createDecipher.*des|desecb|DES\.encrypt)").unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in JavaScript - DES is insecure; use AES-256 or stronger",
    },

    // JavaScript/Next.js No Rate Limit on API
    SecurityPattern {
        name: "js_no_rate_limit",
        regex: Regex::new(r#"(?i)(?:app|router|NextApiRoute)\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/api"#).unwrap(),
        severity: Severity::Medium,
        message: "Missing rate limiting in JavaScript API - no rate limiter detected",
    },

    // JavaScript/Next.js Missing CSP
    SecurityPattern {
        name: "js_missing_csp",
        regex: Regex::new(r"(?i)(?:getServerSideProps|getStaticProps|export.*function.*Page)").unwrap(),
        severity: Severity::Low,
        message: "Missing CSP in Next.js - ensure Content-Security-Policy header is set",
    },

    // Next.js specific patterns
    SecurityPattern {
        name: "js_nextjs_server_component_exec",
        regex: Regex::new(r#"(?i)(?:exec|spawn|execSync)\s*\([^)]*\)"#).unwrap(),
        severity: Severity::High,
        message: "Command execution in Next.js server component - ensure no user input in command",
    },
    SecurityPattern {
        name: "js_nextjs_dangerous_env",
        regex: Regex::new(r#"(?i)process\.env\.[A-Z_]*\s*===\s*['"]"#).unwrap(),
        severity: Severity::Medium,
        message: "Next.js environment check - sensitive env vars exposed to client",
    },

    // JavaScript CSRF patterns
    SecurityPattern {
        name: "js_csrf_missing_token",
        regex: Regex::new(r#"(?i)(?:app|router)\.(?:post|put|delete|patch)\s*\(\s*['"]\/api"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential CSRF in JavaScript - state-changing endpoint without CSRF token validation",
    },

    // JavaScript IDOR patterns
    SecurityPattern {
        name: "js_idor_params_access",
        regex: Regex::new(r#"(?i)(?:req|request)\.params\.(?:id|userId|user_id|accountId)"#).unwrap(),
        severity: Severity::Medium,
        message: "Potential IDOR in JavaScript - direct use of params.id without authorization check",
    },

    // JavaScript Unsafe Reflection
    SecurityPattern {
        name: "js_unsafe_reflection",
        regex: Regex::new(r#"(?i)(?:eval|Function|setTimeout|setInterval)\("#).unwrap(),
        severity: Severity::High,
        message: "Unsafe reflection in JavaScript - dynamic code execution with user input",
    },
    SecurityPattern {
        name: "js_dynamic_method_call",
        regex: Regex::new(r#"(?i)(?:obj|target|action)\[[^\]]+\]\s*\("#).unwrap(),
        severity: Severity::High,
        message: "Unsafe reflection in JavaScript - dynamic method invocation with user input",
    },

    // JavaScript Race Condition
    SecurityPattern {
        name: "js_race_condition",
        regex: Regex::new(r"(?i)(?:if\s*\([^)]*(?:balance|stock|amount|quantity)[^)]*\).*await|await.*setTimeout)").unwrap(),
        severity: Severity::High,
        message: "Race condition in JavaScript - non-atomic check-then-act; use transactions or locks",
    },

    // JavaScript Prototype Pollution
    SecurityPattern {
        name: "js_prototype_pollution",
        regex: Regex::new(r#"(?i)(?:Object\.assign|Object\.merge|deepAssign|deepMerge)\s*\([^)]*req\."#).unwrap(),
        severity: Severity::Critical,
        message: "Prototype pollution in JavaScript - user input in Object.assign/merge without __proto__ guards",
    },

    // Fastify-specific patterns
    // #606 Header injection
    SecurityPattern {
        name: "js_fastify_header_injection",
        regex: Regex::new(r#"reply\.header\s*\([^)]*request\.(query|body|params)"#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Fastify - user input in response header without validation",
    },

    // #607 LDAP injection
    SecurityPattern {
        name: "js_fastify_ldap_injection",
        regex: Regex::new(r#"ldap\.search\s*\([^)]*request\.(query|body|params)"#).unwrap(),
        severity: Severity::High,
        message: "LDAP injection in Fastify - user input in LDAP query without sanitization",
    },

    // #608 XML injection
    SecurityPattern {
        name: "js_fastify_xml_injection",
        regex: Regex::new(r#"xml2js|fast-xml-parser\([^)]*request\.(query|body|params)"#).unwrap(),
        severity: Severity::High,
        message: "XML injection in Fastify - user input in XML parser without safe settings",
    },

    // #609 ReDoS
    SecurityPattern {
        name: "js_fastify_redos",
        regex: Regex::new(r#"new\s+RegExp\s*\(\s*request\.(query|body|params)"#).unwrap(),
        severity: Severity::High,
        message: "ReDoS in Fastify - user-controlled input in RegExp can cause denial of service",
    },

    // #610 Zip slip
    SecurityPattern {
        name: "js_fastify_zip_slip",
        regex: Regex::new(r#"(?:unzipper|decompress|adm-zip|jszip)\.Extract\s*\([^)]*request\.(query|body|params)"#).unwrap(),
        severity: Severity::High,
        message: "Zip slip in Fastify - extraction without path validation can overwrite arbitrary files",
    },

    // #611 Unsafe redirect
    SecurityPattern {
        name: "js_fastify_unsafe_redirect",
        regex: Regex::new(r#"reply\.redirect\s*\(\s*request\.(query|body|params)"#).unwrap(),
        severity: Severity::Medium,
        message: "Unsafe redirect in Fastify - reply.redirect with user-controlled URL",
    },

    // Swift/Vapor vulnerability patterns
    // XSS
    SecurityPattern {
        name: "swift_xss",
        regex: Regex::new(r#"Response\(html:\s*["'\)].*?request\."#).unwrap(),
        severity: Severity::High,
        message: "XSS in Swift/Vapor - unescaped user input in HTML response",
    },

    // Path traversal
    SecurityPattern {
        name: "swift_path_traversal",
        regex: Regex::new(r#"FileManager\.|Data\.contentsOf:|contents\s*atPath:"#).unwrap(),
        severity: Severity::High,
        message: "Path traversal in Swift/Vapor - user input in file path without validation",
    },

    // SSRF
    SecurityPattern {
        name: "swift_ssrf",
        regex: Regex::new(r#"Client\.|try await Client\."#).unwrap(),
        severity: Severity::High,
        message: "SSRF in Swift/Vapor - HTTP client with user-controlled URL",
    },

    // Insecure deserialization
    SecurityPattern {
        name: "swift_insecure_deserialization",
        regex: Regex::new(r#"JSONDecoder\(\)\.decode|JSONSerialization\.jsonObject"#).unwrap(),
        severity: Severity::High,
        message: "Insecure deserialization in Swift - decoding untrusted JSON",
    },

    // XXE injection
    SecurityPattern {
        name: "swift_xxe",
        regex: Regex::new(r#"XMLParser\(|XMLDocument\("#).unwrap(),
        severity: Severity::High,
        message: "XXE injection in Swift - parsing XML from user input",
    },

    // Additional Swift/Vapor patterns
    // Unsafe file upload
    SecurityPattern {
        name: "swift_unsafe_upload",
        regex: Regex::new(r#"(?:FileManager|FileHandle|write)\([^)]*request\.files|uploadPath\s*="#).unwrap(),
        severity: Severity::High,
        message: "Unsafe file upload in Swift - user-controlled filename without validation",
    },

    // Insecure random
    SecurityPattern {
        name: "swift_insecure_random",
        regex: Regex::new(r#"Int\.random\(|UInt\.random\(|Double\.random\("#).unwrap(),
        severity: Severity::Medium,
        message: "Insecure random in Swift - Int.random is not cryptographically secure for tokens",
    },

    // Weak crypto
    SecurityPattern {
        name: "swift_weak_crypto",
        regex: Regex::new(r#"Insecure\.|MD5\(|SHA1\(|MessageDigest\.md5"#).unwrap(),
        severity: Severity::High,
        message: "Weak cryptography in Swift - using deprecated MD5/SHA1 for security purposes",
    },

    // Header injection
    SecurityPattern {
        name: "swift_header_injection",
        regex: Regex::new(r#"headers\[[^\]]*\]\s*=.*request\.|Message\s*\([^)]*request\."#).unwrap(),
        severity: Severity::High,
        message: "Header injection in Swift - user input in email/HTTP headers without validation",
    },
]);

// Known hallucinated packages that AI commonly invents (instead of flagging everything NOT in known lists)
static HALLUCINATED_PACKAGES: Lazy<Vec<HallucinationPattern>> = Lazy::new(|| vec![
    HallucinationPattern {
        name: "python_hallucinated",
        regex: Regex::new(r"(?m)^(?:from\s+(\w+(?:\.\w+)*)|import\s+(\w+(?:\.\w+)*))").unwrap(),
        check_imports: |package| {
            let base_package = package.split('.').next().unwrap_or(package);
            // Only flag packages that are commonly hallucinated by AI models
            matches!(base_package, 
                "openai_helper" | "ai_utils" | "chatgpt_api" | "gpt_utils" | "llm_helper" |
                "smart_assistant" | "ai_assistant" | "intelligent_api" | "brain_api" |
                "cognitive_tools" | "neural_network_helper" | "deep_learning_utils" |
                "ml_magic" | "ai_magic" | "super_ai" | "advanced_ai" | "ultimate_ai" |
                "god_mode" | "hack_tools" | "exploit_kit" | "pentesting_suite" |
                "backdoor_utils" | "malware_helper" | "virus_kit" | "trojan_builder" |
                "keylogger_lib" | "steganography_magic" | "cryptography_master" |
                "universal_decoder" | "magic_parser" | "ultra_scraper" | "super_crawler" |
                "omnipotent_lib" | "all_in_one_toolkit" | "universal_helper" |
                "god_library" | "magic_functions" | "ultimate_utils" | "perfect_lib")
        },
    },
    HallucinationPattern {
        name: "js_hallucinated",
        regex: Regex::new(r#"(?:import.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))"#).unwrap(),
        check_imports: |package| {
            // Skip relative imports and file paths
            if package.starts_with('.') || package.starts_with('/') || package.contains('/') {
                return false;
            }
            // Only flag commonly hallucinated npm packages
            matches!(package,
                "openai-helper" | "ai-utils" | "chatgpt-api" | "gpt-utils" | "llm-helper" |
                "smart-assistant" | "ai-assistant" | "intelligent-api" | "brain-api" |
                "cognitive-tools" | "neural-helper" | "deep-learning-utils" |
                "ml-magic" | "ai-magic" | "super-ai" | "advanced-ai" | "ultimate-ai" |
                "god-mode" | "hack-tools" | "exploit-kit" | "pentesting-suite" |
                "backdoor-utils" | "malware-helper" | "virus-kit" | "trojan-builder" |
                "keylogger-lib" | "steganography-magic" | "cryptography-master" |
                "universal-decoder" | "magic-parser" | "ultra-scraper" | "super-crawler" |
                "omnipotent-lib" | "all-in-one-toolkit" | "universal-helper" |
                "god-library" | "magic-functions" | "ultimate-utils" | "perfect-lib")
        },
    },
    HallucinationPattern {
        name: "java_hallucinated",
        regex: Regex::new(r"import\s+(static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*(?:\.\*)?);").unwrap(),
        check_imports: |package| {
            let parts: Vec<&str> = package.split('.').collect();
            if parts.len() < 2 { return false; }
            let base = parts[1];
            // Only flag commonly hallucinated Java packages
            matches!(base,
                "openai" | "chatgpt" | "gpt" | "llm" | "aihelper" | "smartassistant" |
                "intelligentapi" | "brainapi" | "cognitivetools" | "neuralhelper" |
                "mlmagic" | "aimagic" | "superai" | "advancedai" | "ultimateai" |
                "godmode" | "hacktools" | "exploitkit" | "pentestingsuite" |
                "backdoorutils" | "malwarehelper" | "viruskit" | "trojanbuilder" |
                "keyloggerlib" | "steganographymagic" | "cryptographymaster" |
                "universaldecoder" | "magicparser" | "ultrascraper" | "supercrawler")
        },
    },
    HallucinationPattern {
        name: "go_hallucinated",
        regex: Regex::new(r#"import\s+(?:"([^"]+)"|([a-zA-Z_][a-zA-Z0-9_./]*)|(?:\(\s*(?:"[^"]+"\s*)+\)))"#).unwrap(),
        check_imports: |package| {
            let clean_package = package.trim_matches('"').to_lowercase();
            // Only flag commonly hallucinated Go packages
            clean_package.contains("openai-helper") || clean_package.contains("ai-utils") ||
            clean_package.contains("chatgpt-api") || clean_package.contains("gpt-utils") ||
            clean_package.contains("llm-helper") || clean_package.contains("smart-assistant") ||
            clean_package.contains("ai-magic") || clean_package.contains("super-ai") ||
            clean_package.contains("hack-tools") || clean_package.contains("exploit-kit") ||
            clean_package.contains("god-mode") || clean_package.contains("ultimate-ai")
        },
    },
    HallucinationPattern {
        name: "ruby_hallucinated",
        regex: Regex::new(r#"(?:require|gem)\s+['"]([^'"]+)['"]"#).unwrap(),
        check_imports: |package| {
            let base_package = package.split('/').next().unwrap_or(package);
            // Only flag commonly hallucinated Ruby gems
            matches!(base_package,
                "openai_helper" | "ai_utils" | "chatgpt_api" | "gpt_utils" | "llm_helper" |
                "smart_assistant" | "ai_assistant" | "intelligent_api" | "brain_api" |
                "cognitive_tools" | "neural_helper" | "ml_magic" | "ai_magic" |
                "super_ai" | "advanced_ai" | "ultimate_ai" | "god_mode" |
                "hack_tools" | "exploit_kit" | "backdoor_utils" | "malware_helper" |
                "universal_helper" | "magic_functions" | "perfect_lib")
        },
    },
    HallucinationPattern {
        name: "c_hallucinated",
        regex: Regex::new(r#"#include\s+[<"]([^>"]+)[>"]"#).unwrap(),
        check_imports: |package| {
            // Only flag commonly hallucinated C headers
            matches!(package,
                "ai_helper.h" | "neural_network.h" | "machine_learning.h" | "smart_ai.h" |
                "cognitive_tools.h" | "brain_api.h" | "god_mode.h" | "hack_tools.h" |
                "exploit_kit.h" | "backdoor.h" | "malware.h" | "virus.h" |
                "universal_lib.h" | "magic_functions.h" | "ultimate_utils.h" |
                "openai.h" | "chatgpt.h" | "gpt.h" | "llm.h")
        },
    },
    HallucinationPattern {
        name: "cpp_hallucinated",
        regex: Regex::new(r#"#include\s+[<"]([^>"]+)[>"]"#).unwrap(),
        check_imports: |package| {
            // Only flag commonly hallucinated C++ headers  
            matches!(package,
                "ai_helper.hpp" | "neural_network.hpp" | "machine_learning.hpp" | "smart_ai.hpp" |
                "cognitive_tools.hpp" | "brain_api.hpp" | "god_mode.hpp" | "hack_tools.hpp" |
                "exploit_kit.hpp" | "backdoor.hpp" | "malware.hpp" | "virus.hpp" |
                "universal_lib.hpp" | "magic_functions.hpp" | "ultimate_utils.hpp" |
                "openai.hpp" | "chatgpt.hpp" | "gpt.hpp" | "llm.hpp")
        },
    },
]);

/// Top ~50 most critical Python packages (reduced for performance)
static KNOWN_PYTHON_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Python standard library (most common)
        "os", "sys", "json", "re", "datetime", "collections", "itertools", "functools",
        "pathlib", "typing", "asyncio", "threading", "time", "random", "math", "logging",
        "unittest", "argparse", "subprocess", "urllib", "http", "hashlib", "base64",
        "csv", "xml", "io", "tempfile", "glob", "shutil", "copy", "pickle", "warnings",
        "string", "struct", "socket", "email", "gzip", "zipfile", "tarfile", "sqlite3",
        // Most popular PyPI packages
        "requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest", "click",
        "pydantic", "sqlalchemy", "redis", "celery", "boto3", "pillow", "matplotlib",
        "scipy", "sklearn", "tensorflow", "torch", "transformers", "openai", "anthropic",
        "yfinance", "plotly", "seaborn", "statsmodels"
    ].into_iter().collect()
});

/// Top ~50 most critical JavaScript/Node.js packages (reduced for performance)  
static KNOWN_JS_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Node.js built-in modules (most common)
        "fs", "path", "os", "crypto", "http", "https", "url", "util", "events", "stream",
        "buffer", "process", "child_process", "net", "assert", "readline", "zlib",
        // Most popular npm packages
        "react", "react-dom", "express", "lodash", "axios", "moment", "chalk", "commander",
        "debug", "request", "uuid", "async", "bluebird", "webpack", "babel", "eslint",
        "jest", "mocha", "jquery", "vue", "angular", "next", "nuxt", "typescript",
        "socket.io", "mongoose", "sequelize", "prisma", "@prisma/client", "graphql",
        "apollo", "redux", "mobx", "styled-components", "tailwindcss", "bootstrap"
    ].into_iter().collect()
});

/// Top ~50 most critical Java packages (reduced for performance)
static KNOWN_JAVA_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Java Standard Library (most common)
        "java.lang", "java.util", "java.io", "java.net", "java.nio", "java.sql", "java.time",
        "java.text", "java.math", "java.security", "javax.servlet", "javax.persistence",
        // Popular frameworks
        "org.springframework", "org.apache.commons", "com.google.gson", "org.slf4j",
        "junit.framework", "org.junit", "org.mockito", "org.hibernate", "org.apache.http",
        "com.fasterxml.jackson", "org.apache.log4j", "com.zaxxer.hikari", "redis.clients.jedis",
        "org.apache.kafka", "org.elasticsearch", "org.apache.poi", "com.google.guava",
        "org.apache.maven", "org.gradle", "org.apache.camel", "org.apache.cxf"
    ].into_iter().collect()
});

/// Top ~50 most critical Go packages (reduced for performance)
static KNOWN_GO_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Go standard library (most common)
        "fmt", "os", "io", "net/http", "encoding/json", "strings", "strconv", "time",
        "log", "errors", "context", "sync", "runtime", "path", "regexp", "crypto",
        "database/sql", "flag", "bufio", "bytes", "math", "sort", "reflect",
        // Popular third-party packages
        "github.com/gorilla/mux", "github.com/gin-gonic/gin", "github.com/go-redis/redis",
        "gorm.io/gorm", "github.com/sirupsen/logrus", "github.com/spf13/cobra",
        "github.com/stretchr/testify", "google.golang.org/grpc", "github.com/aws/aws-sdk-go",
        "k8s.io/client-go", "github.com/prometheus/client_golang", "go.uber.org/zap"
    ].into_iter().collect()
});

/// Top ~50 most critical Ruby gems (reduced for performance)
static KNOWN_RUBY_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Ruby standard library (most common)
        "json", "yaml", "csv", "uri", "net", "openssl", "digest", "base64", "time",
        "date", "logger", "optparse", "fileutils", "pathname", "tempfile", "thread",
        // Popular Rails ecosystem
        "rails", "activerecord", "activesupport", "actionpack", "activemodel", "rack",
        "devise", "puma", "sidekiq", "rspec", "factory_bot", "faker", "capybara",
        "nokogiri", "httparty", "redis", "pg", "mysql2", "sqlite3", "bcrypt", "jwt"
    ].into_iter().collect()
});

/// Top ~50 most critical C headers (reduced for performance)
static KNOWN_C_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // C standard library (most common)
        "stdio.h", "stdlib.h", "string.h", "math.h", "time.h", "ctype.h", "limits.h",
        "stddef.h", "stdarg.h", "assert.h", "errno.h", "signal.h", "setjmp.h",
        // POSIX headers (most common)
        "unistd.h", "sys/types.h", "sys/stat.h", "sys/socket.h", "netinet/in.h",
        "fcntl.h", "pthread.h", "semaphore.h", "regex.h", "dirent.h", "pwd.h",
        // Popular libraries
        "curl/curl.h", "openssl/ssl.h", "zlib.h", "sqlite3.h", "mysql/mysql.h",
        "json-c/json.h", "pcre.h", "ncurses.h", "SDL.h", "GL/gl.h", "png.h"
    ].into_iter().collect()
});

/// Top ~50 most critical C++ headers (reduced for performance)
static KNOWN_CPP_PACKAGES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // C++ standard library (most common)
        "iostream", "string", "vector", "map", "set", "algorithm", "memory", "functional",
        "utility", "iterator", "exception", "stdexcept", "fstream", "sstream", "thread",
        "mutex", "chrono", "random", "regex", "tuple", "array", "list", "queue", "stack",
        // Popular libraries
        "boost/algorithm.hpp", "boost/asio.hpp", "boost/filesystem.hpp", "opencv2/opencv.hpp",
        "Qt5/QtCore", "eigen3/Eigen/Dense", "json/json.h", "curl/curl.h", "openssl/ssl.h"
    ].into_iter().collect()
});

struct SecurityPattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    message: &'static str,
}

struct HallucinationPattern {
    name: &'static str,
    regex: Regex,
    check_imports: fn(&str) -> bool,
}

/// Code analyzer for detecting issues in source code
pub struct CodeAnalyzer {
    custom_allowlist: Option<CustomAllowlist>,
    signature_analyzer: SignatureAnalyzer,
    type_analyzer: TypeAnalyzer,
    method_analyzer: MethodAnalyzer,
}

struct SignatureAnalyzer {
    suspicious_patterns: Vec<SuspiciousSignature>,
}

struct TypeAnalyzer {
    impossible_combinations: Vec<ImpossibleType>,
}

struct SuspiciousSignature {
    name: &'static str,
    pattern: Regex,
    message: &'static str,
}

struct ImpossibleType {
    name: &'static str,
    pattern: Regex,
    message: &'static str,
}

struct MethodAnalyzer {
    python_stdlib_methods: std::collections::HashMap<&'static str, Vec<&'static str>>,
    javascript_stdlib_methods: std::collections::HashMap<&'static str, Vec<&'static str>>,
    common_wrong_signatures: Vec<WrongSignaturePattern>,
}

struct WrongSignaturePattern {
    name: &'static str,
    pattern: Regex,
    correct_usage: &'static str,
    message: &'static str,
}

impl SignatureAnalyzer {
    fn new() -> Self {
        SignatureAnalyzer {
            suspicious_patterns: vec![
                SuspiciousSignature {
                    name: "impossible_params",
                    pattern: Regex::new(r"def\s+\w+\([^)]*\w+:\s*(?:str|int|float|bool),\s*\w+:\s*(?:str|int|float|bool),\s*\w+:\s*(?:str|int|float|bool),\s*\w+:\s*(?:str|int|float|bool),\s*\w+:\s*(?:str|int|float|bool),\s*\w+:\s*(?:str|int|float|bool)").unwrap(),
                    message: "Suspicious function signature: too many simple parameters (possible AI hallucination)",
                },
                SuspiciousSignature {
                    name: "magic_returns",
                    pattern: Regex::new(r"def\s+\w+\([^)]*\)\s*->\s*(?:Optional\[Dict\[str,\s*Any\]\]|Union\[str,\s*int,\s*float,\s*bool\]|Tuple\[str,\s*str,\s*str,\s*str\])").unwrap(),
                    message: "Overly complex return type annotation (possible AI generation)",
                },
                SuspiciousSignature {
                    name: "excessive_generics",
                    pattern: Regex::new(r"<\w+,\s*\w+,\s*\w+,\s*\w+,\s*\w+>").unwrap(),
                    message: "Excessive generic parameters (possible AI hallucination)",
                },
                SuspiciousSignature {
                    name: "impossible_method_chains",
                    pattern: Regex::new(r"\.\w+\(\)\.\w+\(\)\.\w+\(\)\.\w+\(\)\.\w+\(\)").unwrap(),
                    message: "Extremely long method chain (possible AI hallucination)",
                },
                SuspiciousSignature {
                    name: "contradictory_names",
                    pattern: Regex::new(r"(?:async\s+def\s+sync_\w+|def\s+async_\w+|sync.*async|get.*delete|create.*destroy)").unwrap(),
                    message: "Contradictory function naming (possible AI confusion)",
                },
            ],
        }
    }
}

impl TypeAnalyzer {
    fn new() -> Self {
        TypeAnalyzer {
            impossible_combinations: vec![
                ImpossibleType {
                    name: "string_plus_int",
                    pattern: Regex::new(r#"["'][^"']*["']\s*\+\s*\d+|\d+\s*\+\s*["'][^"']*["']"#).unwrap(),
                    message: "String + integer operation without conversion (type error)",
                },
                ImpossibleType {
                    name: "dict_list_confusion",
                    pattern: Regex::new(r"\.append\(\)\s*\[|\[.*\]\.append\(.*\)\.get\(").unwrap(),
                    message: "Mixed dict/list operations (type confusion)",
                },
                ImpossibleType {
                    name: "impossible_comparisons",
                    pattern: Regex::new(r#"["'][^"']*["']\s*[<>]=?\s*\d+|\d+\s*[<>]=?\s*["'][^"']*["']"#).unwrap(),
                    message: "String/number comparison without conversion",
                },
                ImpossibleType {
                    name: "wrong_api_usage",
                    pattern: Regex::new(r"requests\.get\([^)]*method\s*=|requests\.post\([^)]*get\s*=|json\.loads\([^)]*encoding=").unwrap(),
                    message: "Incorrect API method usage (possible AI hallucination)",
                },
                ImpossibleType {
                    name: "filesystem_type_error",
                    pattern: Regex::new(r"open\([^)]*mode\s*=\s*\d+|os\.path\.join\(\d+").unwrap(),
                    message: "Incorrect filesystem operation types",
                },
                ImpossibleType {
                    name: "datetime_confusion",
                    pattern: Regex::new(r"datetime\.now\(\)\s*\+\s*\d+[^.]|strftime\([^)]*datetime|datetime\.strptime\([^)]*int").unwrap(),
                    message: "Datetime type confusion (missing timedelta/format)",
                },
            ],
        }
    }
}

impl MethodAnalyzer {
    fn new() -> Self {
        let mut python_stdlib_methods = std::collections::HashMap::new();
        let mut javascript_stdlib_methods = std::collections::HashMap::new();
        
        // Python stdlib methods - curated list of commonly hallucinated methods
        python_stdlib_methods.insert("os.path", vec!["exists", "join", "dirname", "basename", "abspath", "isfile", "isdir", "split", "splitext", "expanduser", "expandvars", "normpath", "realpath"]);
        python_stdlib_methods.insert("str", vec!["strip", "split", "join", "replace", "find", "index", "startswith", "endswith", "upper", "lower", "capitalize", "title", "format", "encode", "decode", "isdigit", "isalpha", "isalnum", "isupper", "islower"]);
        python_stdlib_methods.insert("list", vec!["append", "extend", "insert", "remove", "pop", "index", "count", "sort", "reverse", "copy", "clear"]);
        python_stdlib_methods.insert("dict", vec!["get", "pop", "popitem", "keys", "values", "items", "update", "clear", "copy", "setdefault"]);
        python_stdlib_methods.insert("json", vec!["loads", "dumps", "load", "dump"]);
        python_stdlib_methods.insert("re", vec!["match", "search", "findall", "finditer", "sub", "subn", "split", "compile", "escape"]);
        python_stdlib_methods.insert("sys", vec!["exit", "argv", "path", "version", "platform", "executable", "stdin", "stdout", "stderr"]);
        python_stdlib_methods.insert("pathlib.Path", vec!["exists", "is_file", "is_dir", "mkdir", "rmdir", "unlink", "rename", "read_text", "write_text", "read_bytes", "write_bytes", "iterdir", "glob", "rglob", "parent", "parents", "name", "stem", "suffix", "parts"]);

        // JavaScript/TypeScript stdlib methods - commonly hallucinated methods  
        javascript_stdlib_methods.insert("Array", vec!["push", "pop", "shift", "unshift", "splice", "slice", "concat", "join", "indexOf", "lastIndexOf", "includes", "find", "findIndex", "filter", "map", "reduce", "reduceRight", "forEach", "some", "every", "sort", "reverse", "flat", "flatMap", "fill", "copyWithin"]);
        javascript_stdlib_methods.insert("String", vec!["charAt", "charCodeAt", "concat", "indexOf", "lastIndexOf", "slice", "substring", "substr", "toLowerCase", "toUpperCase", "trim", "trimStart", "trimEnd", "split", "replace", "replaceAll", "match", "search", "includes", "startsWith", "endsWith", "repeat", "padStart", "padEnd"]);
        javascript_stdlib_methods.insert("Object", vec!["keys", "values", "entries", "assign", "create", "defineProperty", "defineProperties", "getOwnPropertyNames", "getOwnPropertyDescriptor", "getPrototypeOf", "setPrototypeOf", "hasOwnProperty", "isPrototypeOf", "freeze", "seal", "isFrozen", "isSealed"]);
        javascript_stdlib_methods.insert("Map", vec!["set", "get", "has", "delete", "clear", "keys", "values", "entries", "forEach"]);
        javascript_stdlib_methods.insert("Set", vec!["add", "has", "delete", "clear", "keys", "values", "entries", "forEach"]);
        javascript_stdlib_methods.insert("Promise", vec!["then", "catch", "finally", "resolve", "reject", "all", "allSettled", "race", "any"]);
        javascript_stdlib_methods.insert("JSON", vec!["parse", "stringify"]);
        javascript_stdlib_methods.insert("Math", vec!["abs", "ceil", "floor", "round", "max", "min", "random", "pow", "sqrt", "sin", "cos", "tan", "log", "exp"]);
        
        // Node.js built-in modules
        javascript_stdlib_methods.insert("path", vec!["join", "resolve", "normalize", "dirname", "basename", "extname", "parse", "format", "isAbsolute", "relative", "sep", "delimiter", "posix", "win32"]);
        javascript_stdlib_methods.insert("fs", vec!["readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "exists", "existsSync", "stat", "statSync", "readdir", "readdirSync", "mkdir", "mkdirSync", "rmdir", "rmdirSync", "unlink", "unlinkSync", "rename", "renameSync", "copyFile", "copyFileSync", "access", "accessSync", "watch", "watchFile", "unwatchFile", "createReadStream", "createWriteStream"]);
        javascript_stdlib_methods.insert("os", vec!["arch", "cpus", "endianness", "freemem", "homedir", "hostname", "loadavg", "networkInterfaces", "platform", "release", "tmpdir", "totalmem", "type", "uptime", "userInfo", "version", "EOL"]);
        javascript_stdlib_methods.insert("crypto", vec!["createHash", "createHmac", "createCipher", "createDecipher", "createSign", "createVerify", "pbkdf2", "pbkdf2Sync", "randomBytes", "randomFillSync", "randomFill", "scrypt", "scryptSync", "timingSafeEqual", "constants"]);
        javascript_stdlib_methods.insert("url", vec!["parse", "format", "resolve", "pathToFileURL", "fileURLToPath", "URL", "URLSearchParams"]);
        javascript_stdlib_methods.insert("http", vec!["createServer", "request", "get", "Agent", "Server", "IncomingMessage", "ServerResponse", "ClientRequest"]);
        javascript_stdlib_methods.insert("https", vec!["createServer", "request", "get", "Agent", "Server"]);
        javascript_stdlib_methods.insert("util", vec!["format", "inspect", "isArray", "isRegExp", "isDate", "isError", "inherits", "deprecate", "debuglog", "callbackify", "promisify", "types"]);
        javascript_stdlib_methods.insert("events", vec!["EventEmitter", "once", "on", "addListener", "removeListener", "removeAllListeners", "emit", "listenerCount", "listeners", "eventNames", "setMaxListeners", "getMaxListeners"]);
        
        MethodAnalyzer {
            python_stdlib_methods,
            javascript_stdlib_methods,
            common_wrong_signatures: vec![
                // Python common mistakes
                WrongSignaturePattern {
                    name: "os_path_exist",
                    pattern: Regex::new(r"os\.path\.exist\(").unwrap(),
                    correct_usage: "os.path.exists()",
                    message: "Method 'exist' does not exist on os.path, use 'exists' instead",
                },
                WrongSignaturePattern {
                    name: "str_contains",
                    pattern: Regex::new(r"\.contains\(").unwrap(),
                    correct_usage: "'in' operator or str.find() method",
                    message: "Python strings don't have a 'contains' method, use 'in' operator or find() method",
                },
                WrongSignaturePattern {
                    name: "list_push",
                    pattern: Regex::new(r"\.push\(").unwrap(),
                    correct_usage: "list.append()",
                    message: "Python lists don't have a 'push' method, use 'append' instead",
                },
                WrongSignaturePattern {
                    name: "dict_length",
                    pattern: Regex::new(r"\.length\(\)").unwrap(),
                    correct_usage: "len(dict)",
                    message: "Python objects don't have a 'length()' method, use len() function",
                },
                WrongSignaturePattern {
                    name: "json_parse",
                    pattern: Regex::new(r"json\.parse\(").unwrap(),
                    correct_usage: "json.loads()",
                    message: "Python json module uses 'loads', not 'parse'",
                },
                WrongSignaturePattern {
                    name: "json_stringify",
                    pattern: Regex::new(r"json\.stringify\(").unwrap(),
                    correct_usage: "json.dumps()",
                    message: "Python json module uses 'dumps', not 'stringify'",
                },
                WrongSignaturePattern {
                    name: "path_join_wrong_args",
                    pattern: Regex::new(r"os\.path\.join\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)").unwrap(),
                    correct_usage: "os.path.join() with reasonable number of arguments",
                    message: "Too many arguments for os.path.join(), possible AI hallucination",
                },
                
                // JavaScript common mistakes
                WrongSignaturePattern {
                    name: "array_flatmap_case",
                    pattern: Regex::new(r"\.flatmap\(").unwrap(),
                    correct_usage: "Array.flatMap() (camelCase)",
                    message: "JavaScript Array method is 'flatMap', not 'flatmap'",
                },
                WrongSignaturePattern {
                    name: "array_indexof_case", 
                    pattern: Regex::new(r"\.indexof\(").unwrap(),
                    correct_usage: "Array.indexOf() (camelCase)",
                    message: "JavaScript Array method is 'indexOf', not 'indexof'",
                },
                WrongSignaturePattern {
                    name: "string_indexof_case",
                    pattern: Regex::new(r"\.indexof\(").unwrap(),
                    correct_usage: "String.indexOf() (camelCase)",
                    message: "JavaScript String method is 'indexOf', not 'indexof'",
                },
                WrongSignaturePattern {
                    name: "object_keys_wrong_call",
                    pattern: Regex::new(r"\.keys\(\)").unwrap(),
                    correct_usage: "Object.keys(obj)",
                    message: "Object.keys() is a static method, not an instance method",
                },
                WrongSignaturePattern {
                    name: "array_append",
                    pattern: Regex::new(r"\.append\(").unwrap(),
                    correct_usage: "Array.push()",
                    message: "JavaScript arrays don't have an 'append' method, use 'push' instead",
                },
                WrongSignaturePattern {
                    name: "array_size",
                    pattern: Regex::new(r"\.size\(\)").unwrap(),
                    correct_usage: "Array.length property",
                    message: "JavaScript arrays don't have a 'size()' method, use 'length' property",
                },
                WrongSignaturePattern {
                    name: "string_len",
                    pattern: Regex::new(r"\.len\(\)").unwrap(),
                    correct_usage: "String.length property",
                    message: "JavaScript strings don't have a 'len()' method, use 'length' property",
                },
                
                // Common open() function mistakes
                WrongSignaturePattern {
                    name: "open_too_many_args",
                    pattern: Regex::new(r"open\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)").unwrap(),
                    correct_usage: "open(file, mode='r', encoding=None, ...)",
                    message: "Too many positional arguments for open() function",
                },
                WrongSignaturePattern {
                    name: "open_wrong_mode_type",
                    pattern: Regex::new(r"open\([^)]*,\s*mode\s*=\s*\d+").unwrap(),
                    correct_usage: "open(file, mode='r')",
                    message: "Mode argument should be a string, not a number",
                },
            ],
        }
    }
}

impl Default for CodeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeAnalyzer {
    pub fn new() -> Self {
        Self::with_custom_allowlist(None)
    }

    pub fn with_custom_allowlist(custom_allowlist: Option<CustomAllowlist>) -> Self {
        CodeAnalyzer {
            custom_allowlist,
            signature_analyzer: SignatureAnalyzer::new(),
            type_analyzer: TypeAnalyzer::new(),
            method_analyzer: MethodAnalyzer::new(),
        }
    }
    
    /// Load custom allowlist from .vow/known-packages.yaml
    pub fn load_custom_allowlist() -> Option<CustomAllowlist> {
        let custom_path = Path::new(".vow/known-packages.yaml");
        if custom_path.exists() {
            match std::fs::read_to_string(custom_path) {
                Ok(content) => match serde_yaml::from_str::<CustomAllowlist>(&content) {
                    Ok(allowlist) => Some(allowlist),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse .vow/known-packages.yaml: {}", e);
                        None
                    }
                },
                Err(e) => {
                    eprintln!("Warning: Failed to read .vow/known-packages.yaml: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// Check if a package is in the custom allowlist
    fn is_custom_allowed(&self, package: &str, file_type: &FileType) -> bool {
        if let Some(ref allowlist) = self.custom_allowlist {
            match file_type {
                FileType::Python => {
                    if let Some(ref python_packages) = allowlist.python {
                        return python_packages.iter().any(|p| p == package);
                    }
                }
                FileType::JavaScript | FileType::TypeScript => {
                    if let Some(ref js_packages) = allowlist.javascript {
                        return js_packages.iter().any(|p| {
                            // Handle scoped packages - match either the full name or just the scope
                            p == package || (package.starts_with('@') && p.starts_with(&package.split('/').next().unwrap_or("")))
                        });
                    }
                }
                FileType::Java => {
                    if let Some(ref packages) = allowlist.java {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Go => {
                    if let Some(ref packages) = allowlist.go {
                        return packages.iter().any(|p| package.contains(p));
                    }
                }
                FileType::Ruby => {
                    if let Some(ref packages) = allowlist.ruby {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::C => {
                    if let Some(ref packages) = allowlist.c {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Cpp => {
                    if let Some(ref packages) = allowlist.cpp {
                        return packages.iter().any(|p| p == package);
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if a security pattern should apply to a specific file type
    fn should_apply_pattern(&self, pattern_name: &str, file_type: &FileType, path: &Path) -> bool {
        match pattern_name {
            // YAML/JSON/config patterns - only apply to config files
            "yaml_config_secrets" => {
                matches!(file_type, FileType::Unknown) && 
                path.extension().map_or(false, |ext| {
                    matches!(ext.to_str(), Some("yaml") | Some("yml") | Some("json"))
                })
            },
            "env_file_secrets" => {
                matches!(file_type, FileType::Unknown) && 
                path.file_name().map_or(false, |name| {
                    let name_str = name.to_str().unwrap_or("");
                    name_str.starts_with(".env") || name_str.ends_with(".env")
                })
            },
            // Shell script patterns - only apply to shell files
            "shell_hardcoded_secrets" | "remote_script_pipe" | "curl_bash_oneliner" | "wget_sh_oneliner" |
            "reverse_shell_bash_i" | "reverse_shell_nc_e" | "reverse_shell_perl" | "reverse_shell_python" |
            "reverse_shell_rm_nc" | "cron_injection" | "cron_write_crontab" | "ssh_key_injection" |
            "shell_eval_injection" | "shell_backticks_injection" | "shell_unsafe_reflection" | "insecure_temp_file" |
            "sudo_nopasswd" | "insecure_telnet" | "insecure_ftp" | "insecure_rsh" |
            "shell_var_injection" | "shell_weak_crypto" | "shell_missing_rate_limit" |
            "shell_path_traversal" | "shell_ssrf" => {
                matches!(file_type, FileType::Unknown | FileType::Shell) && 
                path.extension().map_or(false, |ext| {
                    matches!(ext.to_str(), Some("sh") | Some("bash") | Some("zsh") | Some("fish"))
                })
            },
            // Language-specific SQL injection patterns
            "sql_injection_python" => matches!(file_type, FileType::Python),
            "python_flask_xss" | "python_path_traversal" | "python_ssrf" |
            "python_template_injection" | "python_xml_injection" | "python_flask_redirect" |
            "python_header_injection" | "python_format_string" | "python_xpath_injection" |
            "python_unsafe_upload" | "python_xxe" |
            "python_fastapi_xss" | "python_fastapi_path_traversal" | 
            "python_fastapi_ssrf" | "python_fastapi_ldap_injection" => matches!(file_type, FileType::Python),
            "sql_injection_php" => matches!(file_type, FileType::PHP),
            "sql_injection_js" => matches!(file_type, FileType::JavaScript | FileType::TypeScript),
            "sql_injection_java" => matches!(file_type, FileType::Java),
            "sql_injection_go" => matches!(file_type, FileType::Go),
            "sql_injection_ruby" => matches!(file_type, FileType::Ruby),
            // Ruby/Rails patterns
            "ruby_xss_erb" | "ruby_path_traversal" | "ruby_ssrf" | "ruby_yaml_load" | 
            "ruby_xxe" | "ruby_template_injection" | "ruby_insecure_deserialization" |
            "ruby_ldap_injection" | "ruby_header_injection" | "ruby_open_redirect" |
            "ruby_mass_assignment" | "ruby_unsafe_upload" | "ruby_redos" => matches!(file_type, FileType::Ruby),
            // Node.js specific patterns
            "node_tls_reject_disabled" => matches!(file_type, FileType::JavaScript | FileType::TypeScript),
            // Python specific patterns
            "python_ssl_unverified_context" | "requests_verify_false" => matches!(file_type, FileType::Python),
            // JavaScript/TypeScript prototype pollution
            "prototype_pollution_merge" | "prototype_pollution_unsafe" | "proto_assignment" => {
                matches!(file_type, FileType::JavaScript | FileType::TypeScript)
            },
            // Java XXE patterns
            "java_xxe_documentbuilder" | "java_xxe_saxparser" | "java_xxe_xmlreader" | "java_xxe_transformer" => {
                matches!(file_type, FileType::Java)
            },
            // Java/Servlet security patterns (#468-#499)
            p if p.starts_with("java_") => {
                matches!(file_type, FileType::Java)
            },
            // Dart/Flutter specific patterns
            "dart_insecure_filemode_0777" | "dart_insecure_filemode_world_write" | 
            "dart_setPermissions_777" | "dart_setPermissions_world_write" |
            "dart_sql_injection" | "dart_command_injection" | "dart_path_traversal" |
            "dart_ssrf" | "dart_xss" | "dart_unsafe_deserialization" |
            "dart_intent_injection" | "dart_deeplink_injection" |
            "dart_hardcoded_secrets" | "dart_unsafe_reflection" | "dart_insecure_random" |
            "dart_buffer_overflow" | "dart_unsafe_uri" | "dart_insecure_webview" |
            "dart_unvalidated_redirect" | "dart_insecure_asset" | "dart_dynamic_code" |
            "dart_redos" | "dart_unvalidated_intent" => {
                matches!(file_type, FileType::Dart)
            },
            // Swift/Vapor patterns
            "swift_xss" | "swift_path_traversal" | "swift_ssrf" |
            "swift_insecure_deserialization" | "swift_xxe" |
            "swift_unsafe_upload" | "swift_insecure_random" |
            "swift_weak_crypto" | "swift_header_injection" => {
                matches!(file_type, FileType::Swift)
            },
            // Go/net/http specific patterns
            p if p.starts_with("go_") => {
                matches!(file_type, FileType::Go)
            },
            // TypeScript/Express specific patterns (#500-#526)
            p if p.starts_with("ts_express_") => {
                matches!(file_type, FileType::JavaScript | FileType::TypeScript)
            },
            // JavaScript/React/Next.js specific patterns
            p if p.starts_with("js_nextjs_") || p.starts_with("js_") => {
                matches!(file_type, FileType::JavaScript | FileType::TypeScript)
            },
            // General patterns that apply to all code files
            _ => !matches!(file_type, FileType::Unknown)
        }
    }

    /// Analyze code file for potential issues (optimized version)
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = detect_code_type(path);
        let mut issues = Vec::new();
        
        // Run security pattern detection (optimized to process line by line only once)
        for (line_num, line) in content.lines().enumerate() {
            for pattern in SECURITY_PATTERNS.iter() {
                // Apply file-type filtering for specific patterns
                if self.should_apply_pattern(&pattern.name, &file_type, path) && pattern.regex.is_match(line) {
                    issues.push(Issue {
                        severity: pattern.severity.clone(),
                        message: pattern.message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some(pattern.name.to_string()),
                    suggestion: None,
                });
                }
            }
        }
        
        // Run hallucinated API detection (optimized to avoid re-scanning content)
        self.detect_hallucinated_apis(content, &file_type, &mut issues);
        
        // Run signature analysis for suspicious function patterns
        self.analyze_suspicious_signatures(content, &mut issues);
        
        // Run type analysis for impossible type combinations
        self.analyze_type_errors(content, &file_type, &mut issues);
        
        // Run method signature analysis for hallucinated function signatures
        self.analyze_method_signatures(content, &file_type, &mut issues);
        
        AnalysisResult {
            path: path.to_path_buf(),
            file_type: file_type.clone(),
            issues,
            trust_score: 100, // Will be recalculated in lib.rs
        }
    }
    
    fn detect_hallucinated_apis(&self, content: &str, file_type: &FileType, issues: &mut Vec<Issue>) {
        let pattern_name = match file_type {
            FileType::Python => "python_hallucinated",
            FileType::JavaScript | FileType::TypeScript => "js_hallucinated",
            FileType::Java => "java_hallucinated",
            FileType::Go => "go_hallucinated",
            FileType::Ruby => "ruby_hallucinated",
            FileType::C => "c_hallucinated",
            FileType::Cpp => "cpp_hallucinated",
            _ => return,
        };
        
        let pattern = HALLUCINATED_PACKAGES.iter().find(|p| p.name == pattern_name);
        
        if let Some(pattern) = pattern {
            for (line_num, line) in content.lines().enumerate() {
                for captures in pattern.regex.captures_iter(line) {
                    // Get the package name from either capture group
                    let package = captures.get(1).or_else(|| captures.get(2))
                        .map(|m| m.as_str())
                        .unwrap_or("");
                    
                    if !package.is_empty() {
                        // Check if package matches known-hallucinated patterns
                        let is_hallucinated = (pattern.check_imports)(package);
                        // Check if it's in custom allowlist (to override false positives)
                        let is_custom_allowed = self.is_custom_allowed(package, file_type);
                        
                        // Only flag if it matches hallucinated patterns AND is not custom-allowed
                        if is_hallucinated && !is_custom_allowed {
                            issues.push(Issue {
                                severity: Severity::Medium,
                                message: format!("Potentially hallucinated package import: '{}'", package),
                                line: Some(line_num + 1),
                                rule: Some("hallucinated_api".to_string()),
                                suggestion: Some("REMOVE_LINE".to_string()),
                });
                        }
                    }
                }
            }
        }
    }

    fn analyze_suspicious_signatures(&self, content: &str, issues: &mut Vec<Issue>) {
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.signature_analyzer.suspicious_patterns {
                if pattern.pattern.is_match(line) {
                    issues.push(Issue {
                        severity: Severity::Medium,
                        message: pattern.message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some(pattern.name.to_string()),
                    suggestion: None,
                });
                }
            }
        }
    }

    fn analyze_type_errors(&self, content: &str, file_type: &FileType, issues: &mut Vec<Issue>) {
        // Only run type analysis on languages where it's relevant
        match file_type {
            FileType::Python | FileType::JavaScript | FileType::TypeScript | 
            FileType::Java | FileType::Cpp | FileType::CSharp => {
                for (line_num, line) in content.lines().enumerate() {
                    for pattern in &self.type_analyzer.impossible_combinations {
                        if pattern.pattern.is_match(line) {
                            issues.push(Issue {
                                severity: Severity::High,
                                message: format!("{}: {}", pattern.message, line.trim()),
                                line: Some(line_num + 1),
                                rule: Some(pattern.name.to_string()),
                    suggestion: None,
                });
                        }
                    }
                }
            }
            _ => {} // Skip type analysis for other languages
        }
    }

    fn analyze_method_signatures(&self, content: &str, file_type: &FileType, issues: &mut Vec<Issue>) {
        match file_type {
            FileType::Python => {
                self.analyze_python_method_signatures(content, issues);
            }
            FileType::JavaScript | FileType::TypeScript => {
                self.analyze_javascript_method_signatures(content, issues);
            }
            _ => {} // Skip method analysis for other languages
        }
    }

    fn analyze_python_method_signatures(&self, content: &str, issues: &mut Vec<Issue>) {
        for (line_num, line) in content.lines().enumerate() {
            // First, check for common wrong signature patterns
            for pattern in &self.method_analyzer.common_wrong_signatures {
                if pattern.pattern.is_match(line) {
                    // Skip false positives for JS-style method calls if this is clearly Python
                    if (pattern.name == "array_append" || pattern.name == "array_size" || pattern.name == "string_len") 
                       && !line.contains("def ") && !line.contains("class ") {
                        continue;
                    }
                    
                    issues.push(Issue {
                        severity: Severity::Medium,
                        message: format!("Hallucinated method signature: {}. Correct usage: {}", pattern.message, pattern.correct_usage),
                        line: Some(line_num + 1),
                        rule: Some("hallucinated_signature".to_string()),
                    suggestion: None,
                });
                }
            }
            
            // Check for nonexistent methods on known Python stdlib objects
            self.check_python_stdlib_methods(line, line_num, issues);
        }
    }

    fn analyze_javascript_method_signatures(&self, content: &str, issues: &mut Vec<Issue>) {
        // First, extract all imports to understand module context
        let imports = self.extract_javascript_imports(content);
        
        for (line_num, line) in content.lines().enumerate() {
            // First, check for common wrong signature patterns
            for pattern in &self.method_analyzer.common_wrong_signatures {
                if pattern.pattern.is_match(line) {
                    // Skip Python-specific patterns if this is clearly JavaScript
                    if (pattern.name == "str_contains" || pattern.name == "list_push" || pattern.name == "dict_length") 
                       && !line.contains("function ") && !line.contains("class ") {
                        continue;
                    }
                    
                    issues.push(Issue {
                        severity: Severity::Medium,
                        message: format!("Hallucinated method signature: {}. Correct usage: {}", pattern.message, pattern.correct_usage),
                        line: Some(line_num + 1),
                        rule: Some("hallucinated_signature".to_string()),
                    suggestion: None,
                });
                }
            }
            
            // Check for nonexistent methods on known JavaScript stdlib objects
            self.check_javascript_stdlib_methods_with_imports(line, line_num, &imports, issues);
        }
    }

    fn check_python_stdlib_methods(&self, line: &str, line_num: usize, issues: &mut Vec<Issue>) {
        // Check os.path methods
        if line.contains("os.path.") {
            if let Some(method_call) = extract_method_call(line, "os.path.") {
                if let Some(valid_methods) = self.method_analyzer.python_stdlib_methods.get("os.path") {
                    if !valid_methods.contains(&method_call.as_str()) {
                        // Check for common typos
                        let suggestion = if method_call == "exist" {
                            " (did you mean 'exists'?)"
                        } else if method_call == "joinpath" {
                            " (did you mean 'join'?)"
                        } else if method_call == "dirname_name" || method_call == "path_dirname" {
                            " (did you mean 'dirname'?)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on os.path{}", method_call, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                }
            }
        }
        
        // Check string methods (simplified - look for .method() patterns on string-like contexts)
        if line.contains("\"") || line.contains("'") || line.contains("str(") {
            if let Some(method_call) = extract_string_method_call(line) {
                if let Some(valid_methods) = self.method_analyzer.python_stdlib_methods.get("str") {
                    if !valid_methods.contains(&method_call.as_str()) && is_likely_string_method(&method_call) {
                        let suggestion = if method_call == "contains" {
                            " (use 'in' operator or 'find' method)"
                        } else if method_call == "length" {
                            " (use len() function)"
                        } else if method_call == "substr" {
                            " (use 'substring' or slice notation)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on Python strings{}", method_call, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                }
            }
        }
        
        // Check list methods
        if line.contains(".append(") || line.contains(".extend(") || line.contains("[") {
            if let Some(method_call) = extract_list_method_call(line) {
                if let Some(valid_methods) = self.method_analyzer.python_stdlib_methods.get("list") {
                    if !valid_methods.contains(&method_call.as_str()) && is_likely_list_method(&method_call) {
                        let suggestion = if method_call == "push" {
                            " (use 'append' method)"
                        } else if method_call == "length" {
                            " (use len() function)"
                        } else if method_call == "size" {
                            " (use len() function)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on Python lists{}", method_call, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                }
            }
        }
        
        // Check json methods
        if line.contains("json.") {
            if let Some(method_call) = extract_method_call(line, "json.") {
                if let Some(valid_methods) = self.method_analyzer.python_stdlib_methods.get("json") {
                    if !valid_methods.contains(&method_call.as_str()) {
                        let suggestion = if method_call == "parse" {
                            " (use 'loads' method)"
                        } else if method_call == "stringify" {
                            " (use 'dumps' method)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on json module{}", method_call, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                }
            }
        }
    }

    fn extract_javascript_imports(&self, content: &str) -> std::collections::HashMap<String, String> {
        let mut imports = std::collections::HashMap::new();
        
        // Pattern for require() statements: const/let/var name = require('module')
        let require_pattern = Regex::new(r#"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap();
        
        // Pattern for ES6 imports: import name from 'module'  
        let import_pattern = Regex::new(r#"import\s+(\w+)\s+from\s+['"]([^'"]+)['"]"#).unwrap();
        
        // Pattern for destructured imports: import { method } from 'module' or const { method } = require('module')
        let destructured_require_pattern = Regex::new(r#"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap();
        let destructured_import_pattern = Regex::new(r#"import\s*\{\s*([^}]+)\s*\}\s*from\s*['"]([^'"]+)['"]"#).unwrap();
        
        for line in content.lines() {
            // Handle standard require/import
            if let Some(captures) = require_pattern.captures(line) {
                if let (Some(var_name), Some(module_name)) = (captures.get(1), captures.get(2)) {
                    imports.insert(var_name.as_str().to_string(), module_name.as_str().to_string());
                }
            }
            
            if let Some(captures) = import_pattern.captures(line) {
                if let (Some(var_name), Some(module_name)) = (captures.get(1), captures.get(2)) {
                    imports.insert(var_name.as_str().to_string(), module_name.as_str().to_string());
                }
            }
            
            // Handle destructured imports - for now, just track the module
            if let Some(captures) = destructured_require_pattern.captures(line) {
                if let Some(module_name) = captures.get(2) {
                    let methods = captures.get(1).map_or("", |m| m.as_str());
                    // Extract individual method names from destructuring
                    for method in methods.split(',') {
                        let method = method.trim();
                        imports.insert(method.to_string(), module_name.as_str().to_string());
                    }
                }
            }
            
            if let Some(captures) = destructured_import_pattern.captures(line) {
                if let Some(module_name) = captures.get(2) {
                    let methods = captures.get(1).map_or("", |m| m.as_str());
                    for method in methods.split(',') {
                        let method = method.trim();
                        imports.insert(method.to_string(), module_name.as_str().to_string());
                    }
                }
            }
        }
        
        imports
    }

    fn check_javascript_stdlib_methods_with_imports(&self, line: &str, line_num: usize, imports: &std::collections::HashMap<String, String>, issues: &mut Vec<Issue>) {
        // First check for module method calls like path.join()
        if let Some((var_name, method_name)) = extract_module_method_call(line) {
            if let Some(module_name) = imports.get(&var_name) {
                if let Some(valid_methods) = self.method_analyzer.javascript_stdlib_methods.get(module_name.as_str()) {
                    if !valid_methods.contains(&method_name.as_str()) {
                        let suggestion = if module_name == "path" && method_name == "joinPath" {
                            " (use 'join' method)"
                        } else if module_name == "fs" && method_name == "exist" {
                            " (use 'existsSync' or 'exists' method)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on {} module{}", method_name, module_name, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                    // Method is valid for this module, so we're done - don't run generic checks
                    return;
                } else {
                    // Unknown module, continue with generic checks
                }
            } else {
                // Variable not found in imports, it might be a generic method call
                // Continue with generic checks
            }
        }
        
        // Only run generic checks if module-specific checks didn't handle it
        self.check_javascript_stdlib_methods(line, line_num, issues);
    }

    fn check_javascript_stdlib_methods(&self, line: &str, line_num: usize, issues: &mut Vec<Issue>) {
        // Check Array methods
        if line.contains(".map(") || line.contains(".filter(") || line.contains(".push(") || line.contains("[") {
            if let Some(method_call) = extract_js_array_method_call(line) {
                if let Some(valid_methods) = self.method_analyzer.javascript_stdlib_methods.get("Array") {
                    if !valid_methods.contains(&method_call.as_str()) && is_likely_array_method(&method_call) {
                        let suggestion = if method_call == "append" {
                            " (use 'push' method)"
                        } else if method_call == "length" {
                            " (use 'length' property, not method)"
                        } else if method_call == "size" {
                            " (use 'length' property)"
                        } else if method_call == "flatmap" {
                            " (use 'flatMap' with correct capitalization)"
                        } else if method_call == "indexof" {
                            " (use 'indexOf' with correct capitalization)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on JavaScript Array{}", method_call, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                }
            }
        }
        
        // Check String methods
        if line.contains("\"") || line.contains("'") || line.contains("`") {
            if let Some(method_call) = extract_js_string_method_call(line) {
                if let Some(valid_methods) = self.method_analyzer.javascript_stdlib_methods.get("String") {
                    if !valid_methods.contains(&method_call.as_str()) && is_likely_string_method(&method_call) {
                        let suggestion = if method_call == "contains" {
                            " (use 'includes' method)"
                        } else if method_call == "length" {
                            " (use 'length' property, not method)"
                        } else if method_call == "indexof" {
                            " (use 'indexOf' with correct capitalization)"
                        } else {
                            ""
                        };
                        
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Method '{}' does not exist on JavaScript String{}", method_call, suggestion),
                            line: Some(line_num + 1),
                            rule: Some("nonexistent_method".to_string()),
                    suggestion: None,
                });
                    }
                }
            }
        }
        
        // Check Object static method calls that are used incorrectly as instance methods
        if line.contains(".keys()") || line.contains(".values()") || line.contains(".entries()") {
            issues.push(Issue {
                severity: Severity::High,
                message: "Object.keys/values/entries are static methods - use Object.keys(obj), not obj.keys()".to_string(),
                line: Some(line_num + 1),
                rule: Some("incorrect_static_method".to_string()),
                    suggestion: None,
                });
        }
    }
}

// Helper functions for method extraction
fn extract_module_method_call(line: &str) -> Option<(String, String)> {
    // Pattern to match variable.method() calls
    let method_pattern = Regex::new(r"(\w+)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap();
    if let Some(captures) = method_pattern.captures(line) {
        if let (Some(var_match), Some(method_match)) = (captures.get(1), captures.get(2)) {
            return Some((var_match.as_str().to_string(), method_match.as_str().to_string()));
        }
    }
    None
}

fn extract_method_call(line: &str, prefix: &str) -> Option<String> {
    if let Some(start) = line.find(prefix) {
        let after_prefix = &line[start + prefix.len()..];
        if let Some(paren_pos) = after_prefix.find('(') {
            let method_name = &after_prefix[..paren_pos];
            if method_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(method_name.to_string());
            }
        }
    }
    None
}

fn extract_string_method_call(line: &str) -> Option<String> {
    // Look for patterns like .method() that might be string methods
    let method_pattern = Regex::new(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap();
    if let Some(captures) = method_pattern.captures(line) {
        if let Some(method_match) = captures.get(1) {
            return Some(method_match.as_str().to_string());
        }
    }
    None
}

fn extract_list_method_call(line: &str) -> Option<String> {
    // Similar to string method extraction but look for list-like contexts
    let method_pattern = Regex::new(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap();
    if let Some(captures) = method_pattern.captures(line) {
        if let Some(method_match) = captures.get(1) {
            return Some(method_match.as_str().to_string());
        }
    }
    None
}

fn extract_js_array_method_call(line: &str) -> Option<String> {
    let method_pattern = Regex::new(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap();
    if let Some(captures) = method_pattern.captures(line) {
        if let Some(method_match) = captures.get(1) {
            return Some(method_match.as_str().to_string());
        }
    }
    None
}

fn extract_js_string_method_call(line: &str) -> Option<String> {
    let method_pattern = Regex::new(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap();
    if let Some(captures) = method_pattern.captures(line) {
        if let Some(method_match) = captures.get(1) {
            return Some(method_match.as_str().to_string());
        }
    }
    None
}

fn is_likely_string_method(method_name: &str) -> bool {
    matches!(method_name, 
        "contains" | "length" | "substr" | "len" | "size" | "count" |
        "indexof" | "lastindexof" | "substring" | "capitalize" | 
        "trim" | "ltrim" | "rtrim" | "split" | "join" | "replace"
    )
}

fn is_likely_list_method(method_name: &str) -> bool {
    matches!(method_name,
        "push" | "length" | "size" | "len" | "add" | "remove" | 
        "contains" | "get" | "set" | "first" | "last" | "head" | "tail"
    )
}

fn is_likely_array_method(method_name: &str) -> bool {
    matches!(method_name,
        "append" | "length" | "size" | "add" | "remove" | "contains" |
        "flatmap" | "indexof" | "lastindexof" | "foreach" | "reduce" |
        "get" | "set" | "first" | "last" | "head" | "tail"
    )
}

fn detect_code_type(path: &Path) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension.to_lowercase().as_str() {
            "py" => FileType::Python,
            "js" | "jsx" => FileType::JavaScript,
            "ts" | "tsx" => FileType::TypeScript,
            "rs" => FileType::Rust,
            "java" => FileType::Java,
            "go" => FileType::Go,
            "rb" => FileType::Ruby,
            "c" | "h" => FileType::C,
            "cpp" | "cc" | "cxx" | "hpp" => FileType::Cpp,
            "cs" => FileType::CSharp,
            "php" => FileType::PHP,
            "swift" => FileType::Swift,
            "kt" | "kts" => FileType::Kotlin,
            "r" => FileType::R,
            "mq5" | "mqh" => FileType::MQL5,
            "scala" => FileType::Scala,
            "pl" | "pm" => FileType::Perl,
            "lua" => FileType::Lua,
            "dart" => FileType::Dart,
            "hs" => FileType::Haskell,
            _ => FileType::Unknown,
        }
    } else {
        FileType::Unknown
    }
}
