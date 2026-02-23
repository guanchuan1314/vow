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
                    });
                }
            }
            
            // Check for nonexistent methods on known Python stdlib objects
            self.check_python_stdlib_methods(line, line_num, issues);
        }
    }

    fn analyze_javascript_method_signatures(&self, content: &str, issues: &mut Vec<Issue>) {
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
                    });
                }
            }
            
            // Check for nonexistent methods on known JavaScript stdlib objects
            self.check_javascript_stdlib_methods(line, line_num, issues);
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
                        });
                    }
                }
            }
        }
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
            });
        }
    }
}

// Helper functions for method extraction
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