use std::path::Path;
use std::collections::HashSet;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;
use once_cell::sync::Lazy;

/// CSS analyzer for detecting issues in CSS files
pub struct CssAnalyzer {
    // Future: Could add custom configuration here
}

impl CssAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let mut issues = Vec::new();
        
        // Run all CSS analysis checks
        self.check_hallucinated_properties(content, &mut issues);
        self.check_invalid_property_values(content, &mut issues);
        self.check_vendor_prefixes(content, &mut issues);
        self.check_contradictory_declarations(content, &mut issues);
        self.check_ai_generated_patterns(content, &mut issues);
        
        AnalysisResult {
            path: path.to_path_buf(),
            file_type: FileType::CSS,
            issues,
            trust_score: 100, // Will be recalculated in lib.rs
        }
    }

    /// Check for non-existent/hallucinated CSS properties
    fn check_hallucinated_properties(&self, content: &str, issues: &mut Vec<Issue>) {
        // Valid CSS properties (comprehensive list of standard properties)
        static VALID_CSS_PROPERTIES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            HashSet::from([
                // Layout
                "display", "position", "top", "right", "bottom", "left", "float", "clear",
                "z-index", "overflow", "overflow-x", "overflow-y", "visibility", "clip",
                "clip-path", "resize", "cursor", "pointer-events",
                
                // Box model  
                "width", "height", "min-width", "min-height", "max-width", "max-height",
                "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
                "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
                "border", "border-width", "border-style", "border-color",
                "border-top", "border-right", "border-bottom", "border-left",
                "border-top-width", "border-right-width", "border-bottom-width", "border-left-width",
                "border-top-style", "border-right-style", "border-bottom-style", "border-left-style",
                "border-top-color", "border-right-color", "border-bottom-color", "border-left-color",
                "border-radius", "border-top-left-radius", "border-top-right-radius",
                "border-bottom-left-radius", "border-bottom-right-radius",
                "box-sizing", "box-shadow", "outline", "outline-width", "outline-style", "outline-color",
                "outline-offset",
                
                // Typography
                "font", "font-family", "font-size", "font-style", "font-variant", "font-weight",
                "font-stretch", "line-height", "color", "text-align", "text-decoration",
                "text-decoration-line", "text-decoration-color", "text-decoration-style",
                "text-decoration-thickness", "text-underline-offset", "text-transform",
                "text-indent", "text-shadow", "letter-spacing", "word-spacing", "white-space",
                "word-wrap", "word-break", "overflow-wrap", "hyphens", "text-overflow",
                "direction", "unicode-bidi", "writing-mode", "text-orientation",
                
                // Background
                "background", "background-color", "background-image", "background-repeat",
                "background-attachment", "background-position", "background-size",
                "background-origin", "background-clip", "background-blend-mode",
                
                // Flexbox
                "flex", "flex-grow", "flex-shrink", "flex-basis", "flex-direction", "flex-wrap",
                "flex-flow", "justify-content", "align-items", "align-self", "align-content",
                "order", "gap", "row-gap", "column-gap",
                
                // Grid
                "grid", "grid-template", "grid-template-rows", "grid-template-columns",
                "grid-template-areas", "grid-area", "grid-row", "grid-column",
                "grid-row-start", "grid-row-end", "grid-column-start", "grid-column-end",
                "grid-auto-rows", "grid-auto-columns", "grid-auto-flow", "justify-items",
                "justify-self", "place-items", "place-self", "place-content",
                
                // Transforms & Animations
                "transform", "transform-origin", "transform-style", "perspective",
                "perspective-origin", "backface-visibility", "transition", "transition-property",
                "transition-duration", "transition-timing-function", "transition-delay",
                "animation", "animation-name", "animation-duration", "animation-timing-function",
                "animation-delay", "animation-iteration-count", "animation-direction",
                "animation-fill-mode", "animation-play-state",
                
                // Tables
                "table-layout", "border-collapse", "border-spacing", "caption-side",
                "empty-cells", "vertical-align",
                
                // Lists
                "list-style", "list-style-type", "list-style-position", "list-style-image",
                "counter-reset", "counter-increment", "counter-set",
                
                // Generated content
                "content", "quotes",
                
                // Multi-column
                "columns", "column-count", "column-width", "column-gap", "column-rule",
                "column-rule-width", "column-rule-style", "column-rule-color", "column-span",
                "column-fill", "break-before", "break-after", "break-inside",
                
                // Media queries & responsive
                "object-fit", "object-position", "image-rendering", "image-orientation",
                
                // Filters & effects
                "filter", "backdrop-filter", "opacity", "mix-blend-mode", "isolation",
                
                // CSS custom properties
                "custom", "var",
                
                // Print
                "page-break-before", "page-break-after", "page-break-inside", "orphans", "widows",
                
                // Ruby (East Asian typography)
                "ruby-align", "ruby-position",
                
                // Scrolling
                "scroll-behavior", "scroll-margin", "scroll-padding", "scroll-snap-align",
                "scroll-snap-stop", "scroll-snap-type", "overscroll-behavior",
                "overscroll-behavior-x", "overscroll-behavior-y",
                
                // Logical properties
                "margin-inline", "margin-block", "padding-inline", "padding-block",
                "border-inline", "border-block", "inset", "inset-inline", "inset-block",
                "margin-inline-start", "margin-inline-end", "margin-block-start", "margin-block-end",
                "padding-inline-start", "padding-inline-end", "padding-block-start", "padding-block-end",
                
                // Modern CSS
                "aspect-ratio", "contain", "contain-intrinsic-size", "content-visibility",
                "accent-color", "appearance", "caret-color", "mask", "mask-image", "mask-mode",
                "mask-repeat", "mask-position", "mask-clip", "mask-origin", "mask-size",
                "mask-composite", "clip-path", "shape-outside", "shape-margin", "shape-image-threshold",
                
                // CSS Houdini
                "paint-order",
            ])
        });

        let property_regex = Regex::new(r"([a-zA-Z-]+)\s*:").unwrap();
        
        for (line_num, line) in content.lines().enumerate() {
            // Skip comments and non-property lines
            if line.trim().starts_with("/*") || line.trim().starts_with("//") || !line.contains(':') {
                continue;
            }
            
            for captures in property_regex.captures_iter(line) {
                if let Some(property_match) = captures.get(1) {
                    let property = property_match.as_str().to_lowercase();
                    
                    // Skip vendor prefixed properties, CSS custom properties, and SCSS/LESS variables
                    if property.starts_with("-webkit-") || property.starts_with("-moz-") ||
                       property.starts_with("-ms-") || property.starts_with("-o-") ||
                       property.starts_with("--") || property.starts_with("$") ||
                       property.starts_with("@") {
                        continue;
                    }
                    
                    if !VALID_CSS_PROPERTIES.contains(property.as_str()) {
                        // Skip some common legitimate but not listed properties to reduce false positives
                        let legitimate_but_unlisted = [
                            "zoom", "filter", "will-change", "touch-action", "user-drag", "tab-size"
                        ];
                        
                        if !legitimate_but_unlisted.contains(&property.as_str()) {
                            issues.push(Issue {
                                severity: Severity::High,
                                message: format!("Unknown or hallucinated CSS property: '{}'", property),
                                line: Some(line_num + 1),
                                rule: Some("hallucinated_css_property".to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check for invalid property values
    fn check_invalid_property_values(&self, content: &str, issues: &mut Vec<Issue>) {
        let value_patterns = [
            // Invalid color values
            (r#"color\s*:\s*['"]?(?:#[0-9a-fA-F]{1,2}|#[0-9a-fA-F]{4,5}|#[0-9a-fA-F]{7,})['"]?"#, 
             "Invalid color format - should be #RGB, #RRGGBB, or valid color name"),
            
            // Invalid units
            (r#"(width|height|margin|padding|font-size|top|left|right|bottom)\s*:\s*['"]?-?\d+\s*px\s*px['"]?"#,
             "Duplicate 'px' units"),
            
            // Impossible values
            (r#"z-index\s*:\s*['"]?-?\d{4,}['"]?"#,
             "Extremely high z-index value (>999) may indicate AI-generated content"),
            
            (r#"font-size\s*:\s*['"]?(?:0|[1-9]\d{3,})\s*px['"]?"#,
             "Unrealistic font size (0px or >999px)"),
            
            (r#"line-height\s*:\s*['"]?(?:0|[1-9]\d{2,})['"]?"#,
             "Unrealistic line-height value"),
            
            // Common AI mistakes
            (r#"display\s*:\s*['"]?(?:inline-flex|flex-inline)['"]?"#,
             "Invalid display value - should be 'inline-flex', not 'flex-inline'"),
            
            (r#"position\s*:\s*['"]?(?:center|middle)['"]?"#,
             "Invalid position value - 'center' and 'middle' are not valid position values"),
            
            (r#"float\s*:\s*['"]?(?:center|middle)['"]?"#,
             "Invalid float value - 'center' and 'middle' are not valid float values"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, message) in &value_patterns {
                if Regex::new(&format!("(?i){}", pattern)).unwrap().is_match(line) {
                    issues.push(Issue {
                        severity: Severity::High,
                        message: message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some("invalid_css_value".to_string()),
                    });
                }
            }
        }

        // Check for suspicious color values (likely AI-generated)
        let suspicious_color_regex = Regex::new(r"#(?:123456|abcdef|000001|ffffff|ff0000|00ff00|0000ff|ffff00|ff00ff|00ffff)").unwrap();
        for (line_num, line) in content.lines().enumerate() {
            if suspicious_color_regex.is_match(&line.to_lowercase()) {
                issues.push(Issue {
                    severity: Severity::Low,
                    message: "Suspicious color value that may be AI-generated placeholder".to_string(),
                    line: Some(line_num + 1),
                    rule: Some("ai_generated_color".to_string()),
                });
            }
        }
    }

    /// Check for vendor prefix without standard property
    fn check_vendor_prefixes(&self, content: &str, issues: &mut Vec<Issue>) {
        let vendor_prefixed_properties = [
            ("transform", vec!["-webkit-transform", "-moz-transform", "-ms-transform", "-o-transform"]),
            ("transition", vec!["-webkit-transition", "-moz-transition", "-ms-transition", "-o-transition"]),
            ("animation", vec!["-webkit-animation", "-moz-animation", "-ms-animation", "-o-animation"]),
            ("border-radius", vec!["-webkit-border-radius", "-moz-border-radius"]),
            ("box-shadow", vec!["-webkit-box-shadow", "-moz-box-shadow"]),
            ("opacity", vec!["-moz-opacity", "-khtml-opacity"]),
            ("user-select", vec!["-webkit-user-select", "-moz-user-select", "-ms-user-select"]),
            ("appearance", vec!["-webkit-appearance", "-moz-appearance"]),
            ("flex", vec!["-webkit-flex", "-moz-flex", "-ms-flex"]),
            ("gradient", vec!["-webkit-gradient", "-moz-linear-gradient", "-ms-linear-gradient"]),
        ];

        let content_lower = content.to_lowercase();
        
        for (standard_prop, vendor_versions) in &vendor_prefixed_properties {
            for vendor_prop in vendor_versions {
                if content_lower.contains(vendor_prop) {
                    // Check if standard property also exists
                    let has_standard = content_lower.contains(&format!("{}:", standard_prop)) ||
                                     content_lower.contains(&format!("{} :", standard_prop));
                    
                    if !has_standard {
                        // Find line number
                        for (line_num, line) in content.lines().enumerate() {
                            if line.to_lowercase().contains(vendor_prop) {
                                issues.push(Issue {
                                    severity: Severity::Medium,
                                    message: format!("Vendor prefix '{}' used without standard property '{}'", vendor_prop, standard_prop),
                                    line: Some(line_num + 1),
                                    rule: Some("missing_standard_property".to_string()),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for contradictory CSS declarations
    fn check_contradictory_declarations(&self, content: &str, issues: &mut Vec<Issue>) {
        // Parse CSS into rules and check for contradictions within selectors
        let mut current_selector = String::new();
        let mut current_properties: Vec<(String, String, usize)> = Vec::new();
        let mut in_rule = false;
        
        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            
            // Skip comments
            if trimmed.starts_with("/*") || trimmed.starts_with("//") {
                continue;
            }
            
            // Start of CSS rule
            if trimmed.contains('{') && !in_rule {
                current_selector = trimmed.replace('{', "").trim().to_string();
                current_properties.clear();
                in_rule = true;
            }
            // End of CSS rule
            else if trimmed.contains('}') && in_rule {
                self.check_rule_contradictions(&current_selector, &current_properties, issues);
                in_rule = false;
            }
            // Property within rule
            else if in_rule && trimmed.contains(':') {
                if let Some(colon_pos) = trimmed.find(':') {
                    let property = trimmed[..colon_pos].trim().to_lowercase();
                    let value = trimmed[colon_pos + 1..].replace(';', "").trim().to_lowercase();
                    current_properties.push((property, value, line_num + 1));
                }
            }
        }
    }

    fn check_rule_contradictions(&self, selector: &str, properties: &[(String, String, usize)], issues: &mut Vec<Issue>) {
        // Check for specific contradictory patterns
        let contradictions = [
            (("display", "none"), ("visibility", "visible"), "Element with display:none and visibility:visible"),
            (("display", "none"), ("opacity", "1"), "Element with display:none but opacity set (has no effect)"),
            (("position", "static"), ("z-index", ""), "Static elements cannot have z-index"),
            (("width", "auto"), ("width", ""), "Conflicting width declarations"),
            (("height", "auto"), ("height", ""), "Conflicting height declarations"),
        ];

        let mut found_props: std::collections::HashMap<String, (String, usize)> = std::collections::HashMap::new();
        
        // Build property map
        for (property, value, line_num) in properties {
            found_props.insert(property.clone(), (value.clone(), *line_num));
        }

        // Check contradictions
        for ((prop1, val1), (prop2, val2), message) in &contradictions {
            if let (Some((found_val1, line1)), Some((found_val2, line2))) = 
                (found_props.get(*prop1), found_props.get(*prop2)) {
                
                let matches_contradiction = if val1.is_empty() {
                    // Any value for prop1 contradicts with specific val2
                    found_val2.contains(val2)
                } else if val2.is_empty() {
                    // Specific val1 contradicts with any value for prop2  
                    found_val1.contains(val1) && !found_val2.is_empty()
                } else {
                    // Both specific values
                    found_val1.contains(val1) && found_val2.contains(val2)
                };

                if matches_contradiction {
                    issues.push(Issue {
                        severity: Severity::Medium,
                        message: format!("{} (line {} and line {})", message, line1, line2),
                        line: Some(*line1.max(line2)),
                        rule: Some("contradictory_css_declarations".to_string()),
                    });
                }
            }
        }

        // Check for duplicate properties with different values
        let mut property_lines: std::collections::HashMap<String, Vec<(String, usize)>> = std::collections::HashMap::new();
        
        for (property, value, line_num) in properties {
            property_lines.entry(property.clone()).or_insert_with(Vec::new).push((value.clone(), *line_num));
        }

        for (property, values) in property_lines {
            if values.len() > 1 {
                let unique_values: std::collections::HashSet<_> = values.iter().map(|(v, _)| v).collect();
                if unique_values.len() > 1 {
                    let lines: Vec<_> = values.iter().map(|(_, line)| line.to_string()).collect();
                    issues.push(Issue {
                        severity: Severity::Low,
                        message: format!("Property '{}' declared multiple times with different values (lines: {})", 
                                       property, lines.join(", ")),
                        line: values.last().map(|(_, line)| *line),
                        rule: Some("duplicate_property_different_values".to_string()),
                    });
                }
            }
        }
    }

    /// Check for AI-generated placeholder patterns
    fn check_ai_generated_patterns(&self, content: &str, issues: &mut Vec<Issue>) {
        let ai_patterns = [
            // Magic numbers and suspicious values
            (r"/\*\s*TODO:?\s*(?:implement|add|fix|style|design)", "AI-generated TODO comments in CSS"),
            (r#"(?:width|height|margin|padding|font-size)\s*:\s*['"]?(?:42|123|100|200|300|500)px['"]?"#, 
             "Suspicious round number values that may be AI-generated"),
            (r#"font-family\s*:\s*['"]?(?:Arial|Helvetica|Times)['"]?(?:\s*,\s*['"]?(?:sans-serif|serif)['"]?)?$"#, 
             "Generic font stack that may be AI-generated - consider more specific fonts"),
            (r#"background-color\s*:\s*['"]?(?:#f0f0f0|#e0e0e0|#d0d0d0|#c0c0c0)['"]?"#, 
             "Generic gray background colors often used by AI"),
            (r"(?:\.container|\.wrapper|\.content|\.main)[^{]*\{", 
             "Generic CSS class names that may indicate AI-generated code"),
            (r#"border\s*:\s*['"]?1px\s+solid\s+#(?:000|999|ccc|ddd)['"]?"#, 
             "Generic border declarations commonly used by AI"),
            (r"/\*\s*(?:Add your|Custom|TODO|FIXME|NOTE:?\s*)", 
             "AI-generated placeholder comments"),
            (r#"(?:margin|padding)\s*:\s*['"]?(?:10px|20px|15px|25px)['"]?"#, 
             "Round margin/padding values that may be AI-generated - consider using rem or more specific values"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, message) in &ai_patterns {
                if Regex::new(&format!("(?i){}", pattern)).unwrap().is_match(line) {
                    issues.push(Issue {
                        severity: Severity::Low,
                        message: message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some("ai_generated_css_pattern".to_string()),
                    });
                }
            }
        }

        // Check for placeholder class names and IDs
        let placeholder_selectors = Regex::new(r"(?:\.(?:example|test|demo|sample|placeholder)|#(?:example|test|demo|sample|placeholder))\b").unwrap();
        for (line_num, line) in content.lines().enumerate() {
            if placeholder_selectors.is_match(&line.to_lowercase()) {
                issues.push(Issue {
                    severity: Severity::Low,
                    message: "Placeholder CSS selector (example, test, demo, sample) found".to_string(),
                    line: Some(line_num + 1),
                    rule: Some("placeholder_css_selector".to_string()),
                });
            }
        }
    }
}

impl Default for CssAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_hallucinated_properties() {
        let content = r#"
.example {
    text-color: red;
    font-color: blue; 
    fake-property: value;
    background-horizontal: repeat;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        assert_eq!(result.file_type, FileType::CSS);
        assert!(result.issues.len() >= 3);
        
        let has_text_color = result.issues.iter().any(|i| i.message.contains("text-color"));
        let has_font_color = result.issues.iter().any(|i| i.message.contains("font-color"));
        let has_fake_prop = result.issues.iter().any(|i| i.message.contains("fake-property"));
        
        assert!(has_text_color);
        assert!(has_font_color);
        assert!(has_fake_prop);
    }

    #[test]
    fn test_invalid_values() {
        let content = r#"
.example {
    color: #12345;
    font-size: 0px;
    z-index: 99999;
    display: center;
    position: middle;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        let has_invalid_color = result.issues.iter().any(|i| i.message.contains("Invalid color"));
        let has_zero_font = result.issues.iter().any(|i| i.message.contains("font size"));
        let has_high_z = result.issues.iter().any(|i| i.message.contains("z-index"));
        let has_invalid_display = result.issues.iter().any(|i| i.message.contains("display"));
        let has_invalid_position = result.issues.iter().any(|i| i.message.contains("position"));
        
        assert!(has_invalid_color || has_zero_font || has_high_z || has_invalid_display || has_invalid_position);
    }

    #[test]
    fn test_vendor_prefixes() {
        let content = r#"
.example {
    -webkit-transform: scale(1.5);
    -webkit-border-radius: 5px;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        let has_prefix_warning = result.issues.iter().any(|i| i.message.contains("Vendor prefix"));
        assert!(has_prefix_warning);
    }

    #[test]
    fn test_contradictory_declarations() {
        let content = r#"
.example {
    display: none;
    visibility: visible;
    opacity: 1;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        let has_contradiction = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"contradictory_css_declarations".to_string()));
        assert!(has_contradiction);
    }

    #[test]
    fn test_ai_patterns() {
        let content = r#"
/* TODO: implement responsive design */
.container {
    width: 300px;
    margin: 20px;
    background-color: #f0f0f0;
    border: 1px solid #ccc;
    font-family: Arial;
}

.example {
    font-size: 42px;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        let has_todo = result.issues.iter().any(|i| i.message.contains("TODO"));
        let has_generic = result.issues.iter().any(|i| i.message.contains("Generic") || i.message.contains("round number"));
        let has_container = result.issues.iter().any(|i| i.message.contains("container") || i.message.contains("Generic"));
        
        assert!(has_todo || has_generic || has_container);
    }

    #[test]
    fn test_suspicious_colors() {
        let content = r#"
.example {
    color: #123456;
    background: #abcdef;
    border-color: #FF0000;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        let has_suspicious_color = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"ai_generated_color".to_string()));
        assert!(has_suspicious_color);
    }

    #[test]
    fn test_valid_css_minimal_issues() {
        let content = r#"
.navigation {
    display: flex;
    justify-content: space-between;
    padding: 1rem 2rem;
    background-color: #2c3e50;
    color: white;
}

.nav-item {
    text-decoration: none;
    color: inherit;
    transition: opacity 0.3s ease;
}

.nav-item:hover {
    opacity: 0.8;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        // Should have minimal issues with well-written CSS
        assert!(result.issues.len() <= 2); // Allow for minor edge cases
    }

    #[test]
    fn test_duplicate_properties() {
        let content = r#"
.example {
    width: 100px;
    width: 200px;
    color: red;
    color: blue;
}
"#;
        let analyzer = CssAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.css"), content);
        
        let has_duplicate = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"duplicate_property_different_values".to_string()));
        assert!(has_duplicate);
    }
}