use std::path::Path;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;

/// Top ~200 Python packages from PyPI + standard library
const KNOWN_PYTHON_PACKAGES: &[&str] = &[
    // Python standard library modules
    "os", "sys", "subprocess", "json", "urllib", "http", "re", "datetime", "collections", "itertools", 
    "functools", "operator", "pathlib", "typing", "asyncio", "threading", "multiprocessing", "queue",
    "time", "random", "math", "statistics", "decimal", "fractions", "csv", "xml", "html", "email",
    "base64", "hashlib", "hmac", "secrets", "ssl", "socket", "select", "signal", "logging", "unittest",
    "doctest", "argparse", "configparser", "shutil", "tempfile", "glob", "fnmatch", "pickle", "sqlite3",
    "gzip", "zipfile", "tarfile", "io", "struct", "copy", "pprint", "enum", "dataclasses", "contextlib",
    // Popular PyPI packages  
    "requests", "urllib3", "setuptools", "certifi", "pip", "wheel", "six", "python-dateutil", "s3transfer", 
    "botocore", "jmespath", "pyasn1", "rsa", "boto3", "pyyaml", "awscli", "docutils", "colorama", "pyasn1-modules",
    "numpy", "charset-normalizer", "idna", "click", "blinker", "markupsafe", "jinja2", "flask", "werkzeug", "itsdangerous",
    "packaging", "pyparsing", "attrs", "jsonschema", "pyrsistent", "importlib-metadata", "zipp", "typing-extensions",
    "pillow", "cffi", "pycparser", "cryptography", "more-itertools", "pluggy", "py", "wcwidth", "packaging",
    "filelock", "distlib", "platformdirs", "virtualenv", "identify", "nodeenv", "pre-commit", "cfgv", "toml",
    "pytest", "iniconfig", "tomli", "exceptiongroup", "pytest-cov", "coverage", "tornado", "pyzmq", "jupyter-core",
    "traitlets", "jupyter-client", "python-json-logger", "platformdirs", "decorator", "ipython-genutils", "pickleshare",
    "backcall", "matplotlib-inline", "parso", "jedi", "stack-data", "asttokens", "executing", "pure-eval", "ipython",
    "comm", "debugpy", "psutil", "packaging", "nest-asyncio", "jupyter-server", "prometheus-client", "send2trash",
    "terminado", "tinycss2", "pandocfilters", "bleach", "defusedxml", "mistune", "nbformat", "fastjsonschema",
    "jupyter-server-terminals", "websocket-client", "jupyterlab-server", "babel", "json5", "jupyterlab",
    "notebook-shim", "nbconvert", "beautifulsoup4", "soupsieve", "lxml", "html5lib", "webencodings", "cssselect",
    "pyquery", "scrapy", "twisted", "zope-interface", "constantly", "incremental", "automat", "hyperlink",
    "service-identity", "pyopenssl", "queuelib", "w3lib", "parsel", "itemadapter", "itemloaders", "protego",
    "django", "sqlparse", "asgiref", "pytz", "djangorestframework", "markdown", "django-filter", "coreschema",
    "uritemplate", "coreapi", "openapi-codec", "simplejson", "ruamel-yaml", "ruamel-yaml-clib", "inflection",
    "drf-yasg", "uritemplate", "coreapi", "coreschema", "pytest-django", "factory-boy", "faker", "text-unidecode",
    "pandas", "pytz", "numpy", "python-dateutil", "six", "scipy", "matplotlib", "cycler", "kiwisolver", "fonttools",
    "pyparsing", "packaging", "pillow", "contourpy", "importlib-resources", "zipp", "seaborn", "statsmodels", "patsy",
    "scikit-learn", "joblib", "threadpoolctl", "networkx", "sympy", "mpmath", "nltk", "regex", "tqdm", "click",
    "openpyxl", "et-xmlfile", "xlsxwriter", "xlrd", "xlwt", "tabulate", "termcolor", "colorama", "rich", "pygments",
    "markdown-it-py", "mdurl", "textwrap3", "wcwidth", "prompt-toolkit", "pyperclip", "keyboard", "mouse", "pynput",
    "opencv-python", "opencv-contrib-python", "imageio", "imageio-ffmpeg", "moviepy", "proglog", "tqdm", "decorator",
    "requests-oauthlib", "oauthlib", "tweepy", "facebook-sdk", "google-api-python-client", "google-auth-httplib2",
    "google-auth-oauthlib", "google-auth", "cachetools", "pyasn1", "pyasn1-modules", "rsa", "httplib2", "uritemplate",
    "redis", "celery", "kombu", "billiard", "pytz", "click-didyoumean", "click-plugins", "click-repl", "vine",
    "amqp", "cached-property", "importlib-metadata", "zipp", "sqlalchemy", "greenlet", "psycopg2", "psycopg2-binary",
    "pymongo", "dnspython", "motor", "asyncio-mqtt", "paho-mqtt", "pyserial", "pyusb", "libusb1", "hidapi",
    "bleak", "pyble", "gattlib", "bluepy", "pexpect", "ptyprocess", "paramiko", "bcrypt", "pynacl", "sshtunnel",
    "fabric", "invoke", "pathlib2", "scandir", "pathspec", "watchdog", "argh", "pyyaml-include", "environs", "marshmallow",
    "webargs", "apispec", "apispec-webframeworks", "flasgger", "connexion", "clickclick", "inflection", "jsonschema",
    "fastapi", "starlette", "pydantic", "email-validator", "dnspython", "python-multipart", "aiofiles", "uvicorn",
    "gunicorn", "waitress", "gevent", "eventlet", "greenlet", "locust", "pyquery", "geventhttpclient", "websocket-client"
];

/// Top ~200 JavaScript/Node.js packages from npm + Node.js built-ins
const KNOWN_JS_PACKAGES: &[&str] = &[
    // Node.js built-in modules
    "fs", "path", "os", "crypto", "http", "https", "url", "querystring", "util", "events", "stream",
    "buffer", "child_process", "cluster", "dgram", "dns", "domain", "net", "readline", "repl", "tls",
    "tty", "vm", "zlib", "assert", "process", "console", "timers", "module", "worker_threads",
    // Popular npm packages
    "lodash", "chalk", "request", "commander", "express", "debug", "ms", "mkdirp", "colors", "async", "underscore",
    "moment", "bluebird", "q", "uuid", "semver", "yargs", "glob", "minimatch", "inherits", "util-deprecate", "safe-buffer",
    "react", "react-dom", "prop-types", "classnames", "react-router", "react-router-dom", "history", "hoist-non-react-statics",
    "redux", "react-redux", "redux-thunk", "reselect", "immutable", "axios", "isomorphic-fetch", "whatwg-fetch", "node-fetch",
    "jquery", "bootstrap", "popper.js", "@popperjs/core", "moment-timezone", "date-fns", "dayjs", "luxon", "numbro", "numeral",
    "vue", "@vue/cli-service", "vuex", "vue-router", "vuetify", "vue-loader", "vue-template-compiler", "vue-style-loader",
    "angular", "@angular/core", "@angular/common", "@angular/platform-browser", "@angular/router", "@angular/forms",
    "@angular/http", "@angular/animations", "rxjs", "tslib", "zone.js", "@angular/cli", "@angular/compiler-cli",
    "webpack", "webpack-cli", "webpack-dev-server", "html-webpack-plugin", "mini-css-extract-plugin", "css-loader",
    "style-loader", "file-loader", "url-loader", "babel-loader", "ts-loader", "source-map-loader", "terser-webpack-plugin",
    "@babel/core", "@babel/preset-env", "@babel/preset-react", "@babel/preset-typescript", "@babel/plugin-proposal-class-properties",
    "babel-polyfill", "@babel/polyfill", "core-js", "regenerator-runtime", "@babel/runtime", "@babel/helpers",
    "typescript", "ts-node", "@types/node", "@types/react", "@types/react-dom", "@types/jest", "@types/lodash",
    "eslint", "prettier", "husky", "lint-staged", "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
    "eslint-config-prettier", "eslint-plugin-prettier", "eslint-plugin-react", "eslint-plugin-react-hooks",
    "jest", "@testing-library/react", "@testing-library/jest-dom", "@testing-library/user-event", "enzyme", "sinon",
    "mocha", "chai", "supertest", "nyc", "karma", "jasmine", "protractor", "puppeteer", "playwright", "cypress",
    "nodemon", "concurrently", "cross-env", "dotenv", "config", "yargs-parser", "minimist", "optimist", "nopt",
    "express-session", "connect-redis", "passport", "passport-local", "passport-jwt", "jsonwebtoken", "bcryptjs", "bcrypt",
    "mongoose", "sequelize", "typeorm", "prisma", "knex", "bookshelf", "objection", "pg", "mysql2", "sqlite3", "redis",
    "socket.io", "ws", "uws", "sockjs", "engine.io", "primus", "faye-websocket", "websocket", "ws", "isomorphic-ws",
    "nodemailer", "sendgrid", "mailgun-js", "@sendgrid/mail", "emailjs", "mandrill-api", "sparkpost", "ses", "postmark",
    "multer", "formidable", "busboy", "multiparty", "connect-multiparty", "express-fileupload", "gridfs-stream", "multer-gridfs-storage",
    "cors", "helmet", "morgan", "compression", "serve-static", "cookie-parser", "express-validator", "joi", "yup", "ajv",
    "winston", "bunyan", "pino", "log4js", "npmlog", "debug", "signale", "consola", "kleur", "colorette", "ansi-colors",
    "fs-extra", "graceful-fs", "rimraf", "del", "make-dir", "move-file", "copy-file", "cpy", "globby", "fast-glob",
    "chokidar", "gaze", "node-watch", "sane", "watchpack", "webpack-dev-middleware", "webpack-hot-middleware", "react-hot-loader",
    "pm2", "forever", "supervisor", "node-dev", "nodemon", "reload", "livereload", "browser-sync", "lite-server", "serve",
    "http-server", "json-server", "mock-json-server", "nock", "superagent", "got", "bent", "needle", "phin", "cross-fetch"
];

/// Code analyzer for detecting issues in source code
pub struct CodeAnalyzer {
    security_patterns: Vec<SecurityPattern>,
    hallucination_patterns: Vec<HallucinationPattern>,
}

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

impl Default for CodeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeAnalyzer {
    pub fn new() -> Self {
        let security_patterns = vec![
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
        ];

        let hallucination_patterns = vec![
            HallucinationPattern {
                name: "python_imports",
                regex: Regex::new(r"(?m)^(?:from\s+(\w+(?:\.\w+)*)|import\s+(\w+(?:\.\w+)*))").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').next().unwrap_or(package);
                    !KNOWN_PYTHON_PACKAGES.contains(&base_package)
                },
            },
            HallucinationPattern {
                name: "js_imports",
                regex: Regex::new(r#"(?:import.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))"#).unwrap(),
                check_imports: |package| {
                    // Handle scoped packages and relative imports
                    if package.starts_with('.') || package.starts_with('/') {
                        return false; // Relative imports are fine
                    }
                    let base_package = if package.starts_with('@') {
                        package.split('/').take(2).collect::<Vec<_>>().join("/")
                    } else {
                        package.split('/').next().unwrap_or(package).to_string()
                    };
                    !KNOWN_JS_PACKAGES.contains(&base_package.as_str())
                },
            },
        ];

        CodeAnalyzer {
            security_patterns,
            hallucination_patterns,
        }
    }
    
    /// Analyze code file for potential issues
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = detect_code_type(path);
        let mut issues = Vec::new();
        
        // Run security pattern detection
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.security_patterns {
                if pattern.regex.is_match(line) {
                    issues.push(Issue {
                        severity: pattern.severity.clone(),
                        message: pattern.message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some(pattern.name.to_string()),
                    });
                }
            }
        }
        
        // Run hallucinated API detection
        self.detect_hallucinated_apis(content, &file_type, &mut issues);
        
        AnalysisResult {
            path: path.to_path_buf(),
            file_type: file_type.clone(),
            issues,
            trust_score: 100, // Will be recalculated in lib.rs
        }
    }
    
    fn detect_hallucinated_apis(&self, content: &str, file_type: &FileType, issues: &mut Vec<Issue>) {
        let pattern = match file_type {
            FileType::Python => self.hallucination_patterns.iter().find(|p| p.name == "python_imports"),
            FileType::JavaScript | FileType::TypeScript => self.hallucination_patterns.iter().find(|p| p.name == "js_imports"),
            _ => return,
        };
        
        if let Some(pattern) = pattern {
            for (line_num, line) in content.lines().enumerate() {
                for captures in pattern.regex.captures_iter(line) {
                    // Get the package name from either capture group
                    let package = captures.get(1).or_else(|| captures.get(2))
                        .map(|m| m.as_str())
                        .unwrap_or("");
                    
                    if !package.is_empty() && (pattern.check_imports)(package) {
                        issues.push(Issue {
                            severity: Severity::Medium,
                            message: format!("Potentially hallucinated package import: '{}'", package),
                            line: Some(line_num + 1),
                            rule: Some("hallucinated_api".to_string()),
                        });
                    }
                }
            }
        }
    }
}

fn detect_code_type(path: &Path) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension.to_lowercase().as_str() {
            "py" => FileType::Python,
            "js" | "jsx" => FileType::JavaScript,
            "ts" | "tsx" => FileType::TypeScript,
            "rs" => FileType::Rust,
            _ => FileType::Unknown,
        }
    } else {
        FileType::Unknown
    }
}