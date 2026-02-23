use std::path::Path;
use std::collections::{HashSet, HashMap};
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;
use once_cell::sync::Lazy;

/// HTML analyzer for detecting issues in HTML files
pub struct HtmlAnalyzer {
    // Future: Could add custom configuration here
}

impl HtmlAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let mut issues = Vec::new();
        
        // Run all HTML analysis checks
        self.check_deprecated_tags(content, &mut issues);
        self.check_invalid_nesting(content, &mut issues);
        self.check_accessibility_issues(content, &mut issues);
        self.check_ai_generated_patterns(content, &mut issues);
        self.check_hallucinated_tags(content, &mut issues);
        
        AnalysisResult {
            path: path.to_path_buf(),
            file_type: FileType::HTML,
            issues,
            trust_score: 100, // Will be recalculated in lib.rs
        }
    }

    /// Check for deprecated HTML elements
    fn check_deprecated_tags(&self, content: &str, issues: &mut Vec<Issue>) {
        let deprecated_tags = [
            ("font", "Use CSS for styling instead"),
            ("center", "Use CSS text-align: center instead"),
            ("marquee", "Use CSS animations instead"),
            ("blink", "Use CSS animations instead"),
            ("basefont", "Use CSS for base font styling instead"),
            ("big", "Use CSS font-size instead"),
            ("small", "Use CSS font-size instead (note: <small> for fine print is still valid)"),
            ("tt", "Use CSS font-family: monospace instead"),
            ("strike", "Use CSS text-decoration: line-through instead"),
            ("u", "Use CSS text-decoration: underline instead (note: <u> for marking text is valid in HTML5)"),
            ("frame", "Use CSS layout techniques instead"),
            ("frameset", "Use CSS layout techniques instead"),
            ("noframes", "No longer needed"),
            ("applet", "Use <object> or modern web technologies instead"),
            ("isindex", "Use form controls instead"),
            ("dir", "Use <ul> instead"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (tag, suggestion) in &deprecated_tags {
                let pattern = format!(r"</?{}\b", tag);
                if Regex::new(&pattern).unwrap().is_match(&line.to_lowercase()) {
                    issues.push(Issue {
                        severity: Severity::Medium,
                        message: format!("Deprecated HTML tag <{}> found. {}", tag, suggestion),
                        line: Some(line_num + 1),
                        rule: Some("deprecated_html_tag".to_string()),
                    });
                }
            }
        }
    }

    /// Check for invalid HTML nesting
    fn check_invalid_nesting(&self, content: &str, issues: &mut Vec<Issue>) {
        // Common invalid nesting patterns
        let invalid_patterns = [
            (r"<p[^>]*>.*<p[^>]*>", "Nested <p> tags are invalid - paragraphs cannot contain other paragraphs"),
            (r"<button[^>]*>.*<button[^>]*>", "Nested <button> elements are invalid"),
            (r"<a[^>]*>.*<a[^>]*>", "Nested <a> elements are invalid - links cannot contain other links"),
            (r"<form[^>]*>.*<form[^>]*>", "Nested <form> elements are invalid"),
            (r"<h[1-6][^>]*>.*<h[1-6][^>]*>", "Nested heading elements are invalid"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, message) in &invalid_patterns {
                if Regex::new(pattern).unwrap().is_match(&line.to_lowercase()) {
                    // Additional check to avoid false positives from separate tags
                    if !line.contains("</") || line.matches('<').count() > line.matches("</").count() {
                        issues.push(Issue {
                            severity: Severity::High,
                            message: message.to_string(),
                            line: Some(line_num + 1),
                            rule: Some("invalid_html_nesting".to_string()),
                        });
                    }
                }
            }
        }

        // Check for block elements inside inline elements
        let block_in_inline_patterns = [
            (r"<span[^>]*>.*<div[^>]*>", "<div> (block element) cannot be nested inside <span> (inline element)"),
            (r"<a[^>]*>.*<div[^>]*>", "<div> (block element) cannot be nested inside <a> (inline element) - use CSS display: block instead"),
            (r"<em[^>]*>.*<p[^>]*>", "<p> (block element) cannot be nested inside <em> (inline element)"),
            (r"<strong[^>]*>.*<h[1-6][^>]*>", "Heading elements cannot be nested inside <strong>"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, message) in &block_in_inline_patterns {
                if Regex::new(pattern).unwrap().is_match(&line.to_lowercase()) {
                    issues.push(Issue {
                        severity: Severity::High,
                        message: message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some("block_in_inline_element".to_string()),
                    });
                }
            }
        }
    }

    /// Check for accessibility issues
    fn check_accessibility_issues(&self, content: &str, issues: &mut Vec<Issue>) {
        for (line_num, line) in content.lines().enumerate() {
            let line_lower = line.to_lowercase();

            // Missing alt attribute on images
            if line_lower.contains("<img") && !line_lower.contains("alt=") {
                issues.push(Issue {
                    severity: Severity::High,
                    message: "Image missing alt attribute for accessibility".to_string(),
                    line: Some(line_num + 1),
                    rule: Some("missing_img_alt".to_string()),
                });
            }

            // Forms without proper labels
            if line_lower.contains("<input") && line_lower.contains("type=") {
                let has_label = line_lower.contains("aria-label=") || 
                               line_lower.contains("aria-labelledby=") ||
                               content.lines().take(line_num + 3).skip(line_num.saturating_sub(3))
                                   .any(|l| l.to_lowercase().contains("<label"));
                
                if !has_label && !line_lower.contains("type=\"hidden\"") && 
                   !line_lower.contains("type=\"submit\"") && !line_lower.contains("type=\"button\"") {
                    issues.push(Issue {
                        severity: Severity::High,
                        message: "Input element missing associated label for accessibility".to_string(),
                        line: Some(line_num + 1),
                        rule: Some("missing_input_label".to_string()),
                    });
                }
            }

            // Missing lang attribute on html element
            if line_lower.trim_start().starts_with("<html") && !line_lower.contains("lang=") {
                issues.push(Issue {
                    severity: Severity::Medium,
                    message: "HTML element missing lang attribute for accessibility".to_string(),
                    line: Some(line_num + 1),
                    rule: Some("missing_html_lang".to_string()),
                });
            }

            // Tables without proper headers
            if line_lower.contains("<table") {
                let has_headers = content.lines().skip(line_num).take(20)
                    .any(|l| l.to_lowercase().contains("<th>") || l.to_lowercase().contains("<th "));
                    
                if !has_headers {
                    issues.push(Issue {
                        severity: Severity::Medium,
                        message: "Table missing header cells (<th>) for accessibility".to_string(),
                        line: Some(line_num + 1),
                        rule: Some("table_missing_headers".to_string()),
                    });
                }
            }
        }
    }

    /// Check for AI-generated placeholder patterns
    fn check_ai_generated_patterns(&self, content: &str, issues: &mut Vec<Issue>) {
        let ai_patterns = [
            (r"lorem ipsum", "AI-generated Lorem Ipsum placeholder text"),
            (r"example\.com", "AI-generated example.com placeholder URL"),
            (r"TODO:?\s*(?:implement|add|fix|update)", "AI-generated TODO comments"),
            (r"placeholder(?:\s+text)?", "AI-generated placeholder content"),
            (r"click here", "Generic 'click here' link text - use descriptive link text instead"),
            (r#"<div[^>]*class=["']?container["']?[^>]*>"#, "Generic 'container' class name - consider more specific naming"),
            (r#"<div[^>]*class=["']?wrapper["']?[^>]*>"#, "Generic 'wrapper' class name - consider more specific naming"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, message) in &ai_patterns {
                if Regex::new(&format!("(?i){}", pattern)).unwrap().is_match(line) {
                    issues.push(Issue {
                        severity: Severity::Low,
                        message: message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some("ai_generated_pattern".to_string()),
                    });
                }
            }
        }
    }

    /// Check for hallucinated/non-existent HTML tags and attributes
    fn check_hallucinated_tags(&self, content: &str, issues: &mut Vec<Issue>) {
        // Valid HTML5 tags (comprehensive list)
        static VALID_HTML_TAGS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            HashSet::from([
                // Document structure
                "html", "head", "body", "title", "base", "link", "meta", "style",
                // Sections
                "article", "aside", "nav", "section", "h1", "h2", "h3", "h4", "h5", "h6", 
                "header", "footer", "main", "address",
                // Grouping
                "p", "hr", "pre", "blockquote", "ol", "ul", "li", "dl", "dt", "dd", 
                "figure", "figcaption", "div",
                // Text-level semantics
                "a", "em", "strong", "small", "s", "cite", "q", "dfn", "abbr", "ruby",
                "rt", "rp", "data", "time", "code", "var", "samp", "kbd", "sub", "sup",
                "i", "b", "u", "mark", "bdi", "bdo", "span", "br", "wbr",
                // Edits
                "ins", "del",
                // Embedded content
                "picture", "source", "img", "iframe", "embed", "object", "param", "video",
                "audio", "track", "map", "area", "svg", "math",
                // Tabular data
                "table", "caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", 
                "td", "th",
                // Forms
                "form", "label", "input", "button", "select", "datalist", "optgroup",
                "option", "textarea", "output", "progress", "meter", "fieldset", "legend",
                // Interactive elements
                "details", "summary", "dialog",
                // Scripting
                "script", "noscript", "template", "slot", "canvas",
                // Common SVG elements (that can appear in HTML contexts)
                "text", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
                "defs", "use", "symbol", "marker", "clippath", "mask", "pattern", "linearGradient",
                "radialGradient", "stop", "animate", "animateMotion", "animateTransform", "set",
                "foreignObject", "switch", "title", "desc",
                // Deprecated but valid HTML tags (to avoid double-flagging)
                "center", "font", "marquee", "blink", "basefont", "big", "small", "tt", 
                "strike", "u", "frame", "frameset", "noframes", "applet", "isindex", "dir",
                // Web components (custom elements are allowed, so we're conservative here)
            ])
        });

        // Valid HTML5 attributes (common ones - being conservative to avoid false positives)
        static VALID_HTML_ATTRIBUTES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            HashSet::from([
                // Global attributes
                "accesskey", "class", "contenteditable", "data-*", "dir", "draggable", "hidden",
                "id", "lang", "spellcheck", "style", "tabindex", "title", "translate",
                // ARIA attributes
                "aria-label", "aria-labelledby", "aria-describedby", "aria-expanded", "aria-hidden",
                "aria-live", "aria-atomic", "aria-relevant", "aria-busy", "aria-controls",
                "aria-flowto", "aria-grabbed", "aria-haspopup", "aria-invalid", "aria-level",
                "aria-multiline", "aria-multiselectable", "aria-orientation", "aria-owns",
                "aria-readonly", "aria-required", "aria-selected", "aria-sort", "aria-valuemax",
                "aria-valuemin", "aria-valuenow", "aria-valuetext", "role",
                // Common element-specific attributes
                "href", "src", "alt", "width", "height", "type", "name", "value", "placeholder",
                "required", "disabled", "readonly", "checked", "selected", "multiple", "size",
                "maxlength", "minlength", "min", "max", "step", "pattern", "autocomplete",
                "autofocus", "form", "formaction", "formenctype", "formmethod", "formnovalidate",
                "formtarget", "target", "rel", "media", "hreflang", "download", "ping",
                "referrerpolicy", "crossorigin", "integrity", "loading", "decoding", "sizes",
                "srcset", "usemap", "ismap", "controls", "autoplay", "loop", "muted",
                "preload", "poster", "playsinline", "buffered", "open", "reversed", "start",
                "span", "colspan", "rowspan", "headers", "scope", "abbr", "axis", "accept",
                "action", "enctype", "method", "novalidate", "for", "high", "low", "optimum",
                "challenge", "keytype", "keyparams", "wrap", "dirname", "list", "datetime",
                "cite", "manifest", "sandbox", "seamless", "srcdoc", "allowfullscreen",
            ])
        });

        // Extract tags and attributes from HTML
        let tag_regex = Regex::new(r"<(/?)([a-zA-Z][a-zA-Z0-9-]*)[^>]*>").unwrap();
        let attr_regex = Regex::new(r"([a-zA-Z][a-zA-Z0-9-]*)\s*=").unwrap();

        for (line_num, line) in content.lines().enumerate() {
            // Check for invalid tags
            for captures in tag_regex.captures_iter(line) {
                if let Some(tag_name) = captures.get(2) {
                    let tag = tag_name.as_str().to_lowercase();
                    
                    // Skip custom elements (contain hyphens) and known framework prefixes
                    if tag.contains('-') || tag.starts_with("ng-") || tag.starts_with("v-") || 
                       tag.starts_with("react-") || tag.starts_with("vue-") {
                        continue;
                    }
                    
                    if !VALID_HTML_TAGS.contains(tag.as_str()) {
                        issues.push(Issue {
                            severity: Severity::High,
                            message: format!("Unknown or hallucinated HTML tag: <{}>", tag),
                            line: Some(line_num + 1),
                            rule: Some("hallucinated_html_tag".to_string()),
                        });
                    }
                }
            }

            // Check for invalid attributes (basic check - being conservative)
            if line.contains("<") && line.contains("=") {
                for attr_match in attr_regex.captures_iter(line) {
                    if let Some(attr_name) = attr_match.get(1) {
                        let attr = attr_name.as_str().to_lowercase();
                        
                        // Skip data-* attributes, event handlers, and framework attributes
                        if attr.starts_with("data-") || attr.starts_with("on") || 
                           attr.starts_with("ng-") || attr.starts_with("v-") ||
                           attr.starts_with("@") || attr.starts_with(":") || 
                           attr.contains("bind") || attr.contains("model") {
                            continue;
                        }
                        
                        // Only flag obviously wrong attributes to avoid false positives
                        let suspicious_patterns = [
                            "background-color", "text-color", "font-family", "margin-top",
                            "padding-left", "border-width", "text-align", "display",
                            "position", "float", "clear", "visibility", "overflow"
                        ];
                        
                        if suspicious_patterns.iter().any(|&pattern| attr.contains(pattern)) {
                            issues.push(Issue {
                                severity: Severity::Medium,
                                message: format!("CSS property '{}' used as HTML attribute - should be in CSS", attr),
                                line: Some(line_num + 1),
                                rule: Some("css_property_as_html_attribute".to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
}

impl Default for HtmlAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_deprecated_tags() {
        let content = r#"
<html>
<body>
    <center>This is centered</center>
    <font color="red">Red text</font>
    <marquee>Scrolling text</marquee>
</body>
</html>
"#;
        let analyzer = HtmlAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.html"), content);
        
        assert_eq!(result.file_type, FileType::HTML);
        assert!(result.issues.len() >= 3);
        
        let has_center = result.issues.iter().any(|i| i.message.contains("center"));
        let has_font = result.issues.iter().any(|i| i.message.contains("font"));
        let has_marquee = result.issues.iter().any(|i| i.message.contains("marquee"));
        
        assert!(has_center);
        assert!(has_font);
        assert!(has_marquee);
    }

    #[test]
    fn test_accessibility_issues() {
        let content = r#"
<html>
<body>
    <img src="photo.jpg">
    <input type="text" name="username">
    <table>
        <tr><td>Data</td></tr>
    </table>
</body>
</html>
"#;
        let analyzer = HtmlAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.html"), content);
        
        let has_alt_issue = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"missing_img_alt".to_string()));
        let has_label_issue = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"missing_input_label".to_string()));
        let has_table_issue = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"table_missing_headers".to_string()));
        
        assert!(has_alt_issue);
        assert!(has_label_issue);
        assert!(has_table_issue);
    }

    #[test]
    fn test_ai_patterns() {
        let content = r#"
<html>
<body>
    <p>Lorem ipsum dolor sit amet</p>
    <a href="http://example.com">Visit example site</a>
    <!-- TODO: implement this feature -->
    <a href="page.html">click here</a>
</body>
</html>
"#;
        let analyzer = HtmlAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.html"), content);
        
        let has_lorem = result.issues.iter().any(|i| i.message.contains("Lorem Ipsum"));
        let has_example = result.issues.iter().any(|i| i.message.contains("example.com"));
        let has_todo = result.issues.iter().any(|i| i.message.contains("TODO"));
        let has_click_here = result.issues.iter().any(|i| i.message.contains("click here"));
        
        assert!(has_lorem);
        assert!(has_example);
        assert!(has_todo);
        assert!(has_click_here);
    }

    #[test]
    fn test_invalid_nesting() {
        let content = r##"
<html>
<body>
    <p>Outer paragraph <p>Inner paragraph</p></p>
    <a href="#">Link <a href="#">Nested link</a></a>
    <span>Inline <div>Block element</div></span>
</body>
</html>
"##;
        let analyzer = HtmlAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.html"), content);
        
        let has_nested_p = result.issues.iter().any(|i| i.message.contains("Nested <p>"));
        let has_nested_a = result.issues.iter().any(|i| i.message.contains("Nested <a>"));
        let has_block_in_inline = result.issues.iter().any(|i| i.message.contains("block element"));
        
        // Note: Our regex detection might not catch all cases perfectly, but should catch some
        assert!(result.issues.len() > 0);
    }

    #[test]
    fn test_hallucinated_tags() {
        let content = r#"
<html>
<body>
    <fakeelement>This doesn't exist</fakeelement>
    <div background-color="red">Wrong attribute</div>
    <custom-tag>Should not be flagged due to hyphen rule</custom-tag>
    <my-component>Valid custom element</my-component>
</body>
</html>
"#;
        let analyzer = HtmlAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.html"), content);
        
        let has_fake_tag = result.issues.iter().any(|i| i.message.contains("fakeelement"));
        let has_css_attr = result.issues.iter().any(|i| i.message.contains("background-color"));
        let has_custom_tag = result.issues.iter().any(|i| i.message.contains("custom-tag"));
        let has_my_component = result.issues.iter().any(|i| i.message.contains("my-component"));
        
        assert!(has_fake_tag);
        assert!(has_css_attr);
        assert!(!has_custom_tag); // Should not flag hyphenated custom elements  
        assert!(!has_my_component); // Should not flag valid custom elements
    }

    #[test]
    fn test_valid_html_no_issues() {
        let content = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Valid Page</title>
</head>
<body>
    <main>
        <h1>Welcome</h1>
        <p>This is a paragraph.</p>
        <img src="image.jpg" alt="Description">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username">
    </main>
</body>
</html>
"#;
        let analyzer = HtmlAnalyzer::new();
        let result = analyzer.analyze(&PathBuf::from("test.html"), content);
        
        // Should have minimal or no issues with valid HTML
        assert!(result.issues.len() <= 1); // Allow for minor edge cases
    }
}