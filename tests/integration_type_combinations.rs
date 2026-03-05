use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use vow::{analyze_file, FileType, Severity};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_typescript_file_with_type_errors() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.ts");
        
        let content = r#"
interface User {
    name: string;
    age: number;
    active: boolean;
}

function processUser(user: User) {
    // These are type errors that should be detected
    let parts = user.age.split(',');  // number method call as string
    let items: string[] = ["a", "b", "c"];
    user.name.push("new");  // string method call as array
    
    // Boolean arithmetic (implicit conversion)
    let result = user.active + 5;
    
    // This should be valid
    let upperName = user.name.toUpperCase();
    let doubled = user.age * 2;
    
    return {parts, items, result, upperName, doubled};
}

// More complex example with type assertions
function complexExample() {
    let data = getValue() as string;
    // This contradicts the type assertion
    let calculation = data * 10;
    
    // Null assignment and method call
    let nullable = null;
    nullable.toString();
}
"#;
        
        fs::write(&file_path, content).unwrap();
        let result = analyze_file(&file_path).unwrap();
        
        assert_eq!(result.file_type, FileType::TypeScript);
        
        // Count type combination issues specifically
        let type_issues: Vec<_> = result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .collect();
            
        assert!(type_issues.len() >= 4, "Should detect multiple type combination issues: {:?}", 
                type_issues.iter().map(|i| &i.message).collect::<Vec<_>>());
        
        // Check specific issue types
        let has_string_on_number = type_issues.iter().any(|issue| {
            issue.message.contains("string method") && issue.message.contains("number")
        });
        let has_array_on_string = type_issues.iter().any(|issue| {
            issue.message.contains("array method") || issue.message.contains("push")
        });
        let has_null_method_call = type_issues.iter().any(|issue| {
            issue.message.contains("null") && issue.message.contains("Method call")
        });
        let has_type_assertion_contradiction = type_issues.iter().any(|issue| {
            issue.message.contains("asserted as string") || issue.message.contains("arithmetic")
        });
        
        assert!(has_string_on_number, "Should detect string method on number");
        assert!(has_array_on_string, "Should detect array method on string");
        assert!(has_null_method_call, "Should detect method call on null");
        
        // Trust score should be lowered due to multiple issues
        assert!(result.trust_score < 70, "Trust score should be significantly reduced");
    }

    #[test]
    fn test_python_file_with_type_errors() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        
        let content = r#"
# Type annotation examples
def process_data():
    count: int = 42
    name: str = "hello"
    items: list = [1, 2, 3]
    data: dict = {"key": "value"}
    
    # These should trigger type combination errors
    parts = count.split(',')  # int calling string method
    result = name.append("world")  # string calling list method
    value = items.get("key")  # list calling dict method
    sorted_data = data.sort()  # dict calling list method
    
    # String concatenation with number (TypeError in Python)
    message = "Count is: " + count
    other = 10 + "items"
    
    # None method calls
    optional_data = None
    processed = optional_data.strip()
    
    # These should be valid
    upper_name = name.upper()
    doubled_count = count * 2
    first_item = items[0]
    dict_value = data.get("key", "default")

def inferred_types():
    # Test type inference from assignment
    x = 100  # inferred as int
    y = "test"  # inferred as str
    z = [1, 2, 3]  # inferred as list
    w = {"a": 1}  # inferred as dict
    
    # These should be detected as errors
    x_parts = x.lower()  # int calling string method
    y_items = y.pop()    # string calling list method
    z_value = z.keys()   # list calling dict method
    w_length = w.append(5)  # dict calling list method

# Test format method on numbers
def format_test():
    number = 42
    # This should be detected - numbers don't have format method
    formatted = number.format("test")
"#;
        
        fs::write(&file_path, content).unwrap();
        let result = analyze_file(&file_path).unwrap();
        
        assert_eq!(result.file_type, FileType::Python);
        
        // Count type combination issues
        let type_issues: Vec<_> = result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .collect();
            
        assert!(type_issues.len() >= 6, "Should detect multiple type combination issues: {:?}", 
                type_issues.iter().map(|i| &i.message).collect::<Vec<_>>());
        
        // Check for specific patterns
        let has_string_method_on_int = type_issues.iter().any(|issue| {
            issue.message.contains("string method") && (
                issue.message.contains("int") || issue.message.contains("number")
            )
        });
        let has_string_concat_error = type_issues.iter().any(|issue| {
            issue.message.contains("String concatenation") && issue.message.contains("TypeError")
        });
        let has_none_method_call = type_issues.iter().any(|issue| {
            issue.message.contains("None") && issue.message.contains("Method call")
        });
        let has_format_on_number = type_issues.iter().any(|issue| {
            issue.message.contains("format") && issue.message.contains("numbers don't have format method")
        });
        
        assert!(has_string_method_on_int, "Should detect string methods on int");
        assert!(has_string_concat_error, "Should detect string concatenation TypeError");
        assert!(has_none_method_call, "Should detect method call on None");
        assert!(has_format_on_number, "Should detect .format() on number");
        
        // Trust score should be significantly reduced
        assert!(result.trust_score < 60, "Trust score should be very low with many type errors");
    }

    #[test]
    fn test_rust_file_with_type_errors() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        
        let content = r#"
fn main() {
    // Explicit type annotations
    let count: i32 = 42;
    let name: String = "hello".to_string();
    let items: Vec<i32> = vec![1, 2, 3];
    let maybe_value: Option<String> = Some("test".to_string());
    
    // These should trigger critical type combination errors
    let parts = count.split(',');  // i32 calling string method
    let length = count.len();      // i32 calling Vec method
    let result = count.unwrap();   // i32 calling Option method
    
    // String arithmetic (invalid in Rust)
    let invalid = "hello" + 5;
    let also_invalid = 10 * "world";
    
    // Valid operations (should not trigger errors)
    let doubled = count * 2;
    let upper = name.to_uppercase();
    let first = items[0];
    let unwrapped = maybe_value.unwrap_or("default".to_string());
}

fn complex_types() {
    let data: bool = true;
    let numbers: f64 = 3.14;
    
    // These should be detected as errors
    let bool_parts = data.chars();  // bool calling string method
    let float_items = numbers.push(1.0);  // f64 calling Vec method
    
    // Type inference from literals
    let inferred_int = 100;
    let inferred_string = "test";
    let inferred_vec = vec![1, 2, 3];
    let inferred_option = Some(42);
    
    // Errors on inferred types
    let int_split = inferred_int.split(',');  // inferred i32 calling string method
    let string_push = inferred_string.push('x');  // String calling Vec method (close match)
}

// Test Result type confusion
fn result_confusion() {
    let value: String = "test".to_string();
    // This should be detected - String doesn't have unwrap
    let unwrapped = value.unwrap();
}
"#;
        
        fs::write(&file_path, content).unwrap();
        let result = analyze_file(&file_path).unwrap();
        
        assert_eq!(result.file_type, FileType::Rust);
        
        // Count type combination issues
        let type_issues: Vec<_> = result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .collect();
            
        assert!(type_issues.len() >= 4, "Should detect multiple critical type combination issues: {:?}", 
                type_issues.iter().map(|i| &i.message).collect::<Vec<_>>());
        
        // Check for Rust-specific patterns with Critical severity
        let has_critical_string_on_numeric = type_issues.iter().any(|issue| {
            issue.message.contains("string method") && 
            issue.message.contains("numeric type") &&
            issue.severity == Severity::Critical
        });
        let has_critical_vec_on_scalar = type_issues.iter().any(|issue| {
            issue.message.contains("Vec method") && 
            issue.message.contains("scalar type") &&
            issue.severity == Severity::Critical
        });
        let has_critical_option_on_non_option = type_issues.iter().any(|issue| {
            issue.message.contains("Option method") && 
            issue.message.contains("non-Option type") &&
            issue.severity == Severity::Critical
        });
        let has_critical_string_arithmetic = type_issues.iter().any(|issue| {
            issue.message.contains("Arithmetic operation") && 
            issue.message.contains("invalid in Rust") &&
            issue.severity == Severity::Critical
        });
        
        assert!(has_critical_string_on_numeric, "Should detect string methods on numeric types with Critical severity");
        assert!(has_critical_vec_on_scalar, "Should detect Vec methods on scalar types with Critical severity");
        assert!(has_critical_option_on_non_option, "Should detect Option methods on non-Option types with Critical severity");
        assert!(has_critical_string_arithmetic, "Should detect invalid string arithmetic with Critical severity");
        
        // Trust score should be very low with critical issues
        assert!(result.trust_score < 50, "Trust score should be very low with critical type errors");
    }

    #[test]
    fn test_javascript_complex_scenarios() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("complex.js");
        
        let content = r#"
// Complex JavaScript type confusion scenarios
function complexScenarios() {
    // Array constructor confusion
    let arr = new Array(5);
    let parts = arr.split(',');  // Array, not string
    
    // Boolean arithmetic (common in JS but questionable)
    let isActive = true;
    let score = isActive + 10;  // true + 10 = 11
    let multiplied = false * 5;  // false * 5 = 0
    
    // String arithmetic that produces NaN
    let result1 = "hello" * 5;   // NaN
    let result2 = "123" / 2;     // 61.5 (valid but worth noting)
    let result3 = "abc" - 1;     // NaN
    
    // Null/undefined method calls
    let data = null;
    let processed = data.toString();  // TypeError
    
    let undef = undefined;
    let upper = undef.toUpperCase();  // TypeError
    
    // Object vs Array confusion
    let obj = {name: "test", items: []};
    obj.push("new item");  // Objects don't have push
    
    let realArray = [1, 2, 3];
    let value = realArray.get("key");  // Arrays don't have get (like Maps)
}

// Test with assignments and later usage
function assignmentAndUsage() {
    let x = 42;          // number
    let y = "hello";     // string  
    let z = [1, 2, 3];   // array
    let w = {a: 1};      // object
    
    // Several lines later...
    console.log("Processing data...");
    let config = loadConfig();
    
    // These should still be detected
    x.charAt(0);         // number calling string method
    y.push("world");     // string calling array method
    z.get("key");        // array calling object method (if we implement)
    w.splice(0, 1);      // object calling array method
}

// Valid code that should not trigger false positives
function validCode() {
    let count = 5;
    let name = "test";
    let items = [1, 2, 3];
    let config = {debug: true};
    
    // All valid operations
    let doubled = count * 2;
    let upper = name.toUpperCase();
    let first = items[0];
    items.push(4);
    let debug = config.debug;
    let keys = Object.keys(config);
}
"#;
        
        fs::write(&file_path, content).unwrap();
        let result = analyze_file(&file_path).unwrap();
        
        assert_eq!(result.file_type, FileType::JavaScript);
        
        // Count type combination issues
        let type_issues: Vec<_> = result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .collect();
            
        assert!(type_issues.len() >= 5, "Should detect multiple JavaScript type issues: {:?}", 
                type_issues.iter().map(|i| &i.message).collect::<Vec<_>>());
        
        // Check for JavaScript-specific patterns
        let has_array_constructor_confusion = type_issues.iter().any(|issue| {
            issue.message.contains("Array constructor")
        });
        let has_boolean_arithmetic = type_issues.iter().any(|issue| {
            issue.message.contains("Boolean used in arithmetic")
        });
        let has_string_arithmetic = type_issues.iter().any(|issue| {
            issue.message.contains("Arithmetic operation") && 
            issue.message.contains("string") && 
            issue.message.contains("number")
        });
        let has_null_method_calls = type_issues.iter().any(|issue| {
            issue.message.contains("null") || issue.message.contains("undefined")
        });
        
        assert!(has_array_constructor_confusion, "Should detect Array constructor string method confusion");
        assert!(has_boolean_arithmetic, "Should detect boolean arithmetic");
        assert!(has_string_arithmetic, "Should detect string arithmetic operations");
        assert!(has_null_method_calls, "Should detect null/undefined method calls");
        
        // Trust score should be reduced but not as severely as Rust (since JS allows some of this)
        assert!(result.trust_score < 75, "Trust score should be reduced for JavaScript type issues");
    }

    #[test]
    fn test_mixed_valid_and_invalid_code() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("mixed.ts");
        
        let content = r#"
// Mixed valid and invalid TypeScript code
interface Product {
    id: number;
    name: string;
    price: number;
    categories: string[];
}

class ProductService {
    private products: Product[] = [];
    
    addProduct(product: Product): void {
        // Valid operations
        this.products.push(product);
        console.log(`Added ${product.name}`);
        
        // Invalid operations that should be caught
        let parts = product.id.split('-');  // number.split()
        product.categories.get('main');     // array.get()
        
        // More valid operations
        let upperName = product.name.toUpperCase();
        let discountPrice = product.price * 0.9;
    }
    
    processProducts(): void {
        this.products.forEach(product => {
            // Valid
            console.log(product.name.length);
            
            // Invalid
            product.price.charAt(0);  // number.charAt()
        });
    }
    
    // Test type guards and null checks (valid patterns)
    safeAccess(product: Product | null): string {
        if (product && product.name) {
            return product.name.toUpperCase();  // Valid - after null check
        }
        return "Unknown";
    }
    
    // But this should be caught
    unsafeAccess(product: Product | null): string {
        return product.name.toUpperCase();  // Should catch potential null access
    }
}

// More mixed patterns
function utilityFunctions() {
    // Type annotations with errors
    let count: number = 100;
    let text: string = "hello world";
    let flags: boolean = true;
    
    // Valid
    let doubled = count + count;
    let words = text.split(' ');
    let negated = !flags;
    
    // Invalid
    let textParts = count.replace('0', '1');  // number.replace()
    let textLength = flags.length;            // boolean.length
    
    // Edge case: string that looks like a number
    let numericString: string = "123";
    let result = numericString * 2;  // string arithmetic - technically valid in TS/JS but questionable
}
"#;
        
        fs::write(&file_path, content).unwrap();
        let result = analyze_file(&file_path).unwrap();
        
        assert_eq!(result.file_type, FileType::TypeScript);
        
        // Should detect issues but not flag all the valid code
        let type_issues: Vec<_> = result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .collect();
            
        // Should find several issues but not be overwhelmed with false positives
        assert!(type_issues.len() >= 3 && type_issues.len() <= 10, 
                "Should detect reasonable number of issues (3-10), found {}: {:?}", 
                type_issues.len(),
                type_issues.iter().map(|i| &i.message).collect::<Vec<_>>());
        
        // Trust score should reflect the mixed nature - some issues but mostly valid code
        assert!(result.trust_score >= 60 && result.trust_score <= 85, 
                "Trust score should be moderate for mixed valid/invalid code, got {}", result.trust_score);
    }

    #[test] 
    fn test_no_false_positives_on_valid_files() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a completely valid TypeScript file
        let ts_path = temp_dir.path().join("valid.ts");
        let ts_content = r#"
interface User {
    id: number;
    name: string;
    email: string;
    roles: string[];
}

class UserService {
    private users: User[] = [];
    
    addUser(user: User): void {
        this.users.push(user);
    }
    
    findByEmail(email: string): User | undefined {
        return this.users.find(u => u.email === email);
    }
    
    getUserNames(): string[] {
        return this.users.map(u => u.name);
    }
    
    countUsers(): number {
        return this.users.length;
    }
}

function processUser(user: User): string {
    const upperName = user.name.toUpperCase();
    const roleCount = user.roles.length;
    return `${upperName} has ${roleCount} roles`;
}
"#;
        
        fs::write(&ts_path, ts_content).unwrap();
        let ts_result = analyze_file(&ts_path).unwrap();
        
        // Should have no type combination issues in valid code
        let ts_type_issues = ts_result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .count();
        
        assert_eq!(ts_type_issues, 0, "Valid TypeScript code should not trigger type combination issues");
        
        // Create a valid Python file
        let py_path = temp_dir.path().join("valid.py");
        let py_content = r#"
from typing import List, Dict, Optional

class DataProcessor:
    def __init__(self):
        self.data: List[Dict[str, any]] = []
    
    def add_item(self, item: Dict[str, any]) -> None:
        self.data.append(item)
    
    def get_names(self) -> List[str]:
        return [item.get('name', '') for item in self.data]
    
    def count_items(self) -> int:
        return len(self.data)
    
    def process_text(self, text: str) -> str:
        return text.strip().upper()
    
    def calculate_total(self, numbers: List[int]) -> int:
        return sum(numbers)

def utility_function(name: str, count: int, active: bool) -> str:
    if active:
        return f"{name}: {count} items"
    return "Inactive"
"#;
        
        fs::write(&py_path, py_content).unwrap();
        let py_result = analyze_file(&py_path).unwrap();
        
        // Should have no type combination issues in valid code
        let py_type_issues = py_result.issues.iter()
            .filter(|issue| issue.rule.as_ref().map_or(false, |r| r.starts_with("type_combination")))
            .count();
        
        assert_eq!(py_type_issues, 0, "Valid Python code should not trigger type combination issues");
        
        // Both files should have high trust scores
        assert!(ts_result.trust_score >= 90, "Valid TypeScript should have high trust score");
        assert!(py_result.trust_score >= 90, "Valid Python should have high trust score");
    }
}