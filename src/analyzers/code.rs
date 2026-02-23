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

    /// Analyze code file for potential issues (optimized version)
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = detect_code_type(path);
        let mut issues = Vec::new();
        
        // Run security pattern detection (optimized to process line by line only once)
        for (line_num, line) in content.lines().enumerate() {
            for pattern in SECURITY_PATTERNS.iter() {
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
        
        // Run hallucinated API detection (optimized to avoid re-scanning content)
        self.detect_hallucinated_apis(content, &file_type, &mut issues);
        
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
                            });
                        }
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