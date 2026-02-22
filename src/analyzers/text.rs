use std::path::Path;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;

/// Text analyzer for detecting AI-generated content patterns
pub struct TextAnalyzer {
    ai_patterns: Vec<AIPattern>,
}

struct AIPattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    message: &'static str,
}

impl Default for TextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TextAnalyzer {
    pub fn new() -> Self {
        let ai_patterns = vec![
            AIPattern {
                name: "ai_identity",
                regex: Regex::new(r"(?i)\bas an ai\b").unwrap(),
                severity: Severity::High,
                message: "AI self-identification detected: 'as an AI'",
            },
            AIPattern {
                name: "ai_cannot",
                regex: Regex::new(r"(?i)\bi cannot\b").unwrap(),
                severity: Severity::Medium,
                message: "AI limitation phrase detected: 'I cannot'",
            },
            AIPattern {
                name: "ai_delve",
                regex: Regex::new(r"(?i)\bdelve\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored word detected: 'delve' (uncommon in human writing)",
            },
            AIPattern {
                name: "excessive_however",
                regex: Regex::new(r"(?i)\bhowever\b").unwrap(),
                severity: Severity::Low,
                message: "Excessive use of 'however' (common in AI text)",
            },
            AIPattern {
                name: "important_to_note",
                regex: Regex::new(r"(?i)\bit'?s important to note\b").unwrap(),
                severity: Severity::Medium,
                message: "AI hedge phrase detected: 'it's important to note'",
            },
            AIPattern {
                name: "worth_noting",
                regex: Regex::new(r"(?i)\bit'?s worth noting\b").unwrap(),
                severity: Severity::Medium,
                message: "AI hedge phrase detected: 'it's worth noting'",
            },
            AIPattern {
                name: "should_be_noted",
                regex: Regex::new(r"(?i)\bit should be noted\b").unwrap(),
                severity: Severity::Medium,
                message: "AI hedge phrase detected: 'it should be noted'",
            },
            AIPattern {
                name: "furthermore",
                regex: Regex::new(r"(?i)\bfurthermore\b").unwrap(),
                severity: Severity::Low,
                message: "Formal transition word often overused by AI: 'furthermore'",
            },
            AIPattern {
                name: "moreover",
                regex: Regex::new(r"(?i)\bmoreover\b").unwrap(),
                severity: Severity::Low,
                message: "Formal transition word often overused by AI: 'moreover'",
            },
            AIPattern {
                name: "additionally",
                regex: Regex::new(r"(?i)\badditionally\b").unwrap(),
                severity: Severity::Low,
                message: "Formal transition word often overused by AI: 'additionally'",
            },
            AIPattern {
                name: "in_conclusion",
                regex: Regex::new(r"(?i)\bin conclusion\b").unwrap(),
                severity: Severity::Low,
                message: "AI conclusion phrase detected: 'in conclusion'",
            },
            AIPattern {
                name: "to_summarize",
                regex: Regex::new(r"(?i)\bto summarize\b").unwrap(),
                severity: Severity::Low,
                message: "AI summary phrase detected: 'to summarize'",
            },
            AIPattern {
                name: "certainly",
                regex: Regex::new(r"(?i)\bcertainly\b").unwrap(),
                severity: Severity::Low,
                message: "AI affirmation word often overused: 'certainly'",
            },
            AIPattern {
                name: "comprehensive",
                regex: Regex::new(r"(?i)\bcomprehensive\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored adjective: 'comprehensive'",
            },
            AIPattern {
                name: "cutting_edge",
                regex: Regex::new(r"(?i)\bcutting[- ]edge\b").unwrap(),
                severity: Severity::Low,
                message: "AI buzzword detected: 'cutting-edge'",
            },
            AIPattern {
                name: "state_of_the_art",
                regex: Regex::new(r"(?i)\bstate[- ]of[- ]the[- ]art\b").unwrap(),
                severity: Severity::Low,
                message: "AI buzzword detected: 'state-of-the-art'",
            },
            AIPattern {
                name: "paradigm",
                regex: Regex::new(r"(?i)\bparadigm\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored technical term: 'paradigm'",
            },
            AIPattern {
                name: "multifaceted",
                regex: Regex::new(r"(?i)\bmultifaceted\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored descriptor: 'multifaceted'",
            },
            AIPattern {
                name: "plethora",
                regex: Regex::new(r"(?i)\bplethora\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored formal word: 'plethora'",
            },
            AIPattern {
                name: "myriad",
                regex: Regex::new(r"(?i)\bmyriad\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored formal word: 'myriad'",
            },
            AIPattern {
                name: "nuanced",
                regex: Regex::new(r"(?i)\bnuanced\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored descriptor: 'nuanced'",
            },
            AIPattern {
                name: "intricate",
                regex: Regex::new(r"(?i)\bintricate\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored descriptor: 'intricate'",
            },
            AIPattern {
                name: "optimal",
                regex: Regex::new(r"(?i)\boptimal\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored technical term: 'optimal'",
            },
            AIPattern {
                name: "robust",
                regex: Regex::new(r"(?i)\brobust\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored technical descriptor: 'robust'",
            },
            AIPattern {
                name: "seamless",
                regex: Regex::new(r"(?i)\bseamless\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored descriptor: 'seamless'",
            },
            AIPattern {
                name: "utilize",
                regex: Regex::new(r"(?i)\butilize\b").unwrap(),
                severity: Severity::Low,
                message: "AI preference for 'utilize' over 'use'",
            },
            AIPattern {
                name: "facilitate",
                regex: Regex::new(r"(?i)\bfacilitate\b").unwrap(),
                severity: Severity::Low,
                message: "AI-favored formal verb: 'facilitate'",
            },
            AIPattern {
                name: "aforementioned",
                regex: Regex::new(r"(?i)\baforementioned\b").unwrap(),
                severity: Severity::Medium,
                message: "Formal reference term often used by AI: 'aforementioned'",
            },
            AIPattern {
                name: "aforementioned_alternative",
                regex: Regex::new(r"(?i)\bthe above[- ]mentioned\b").unwrap(),
                severity: Severity::Medium,
                message: "Formal reference phrase often used by AI: 'above-mentioned'",
            },
            AIPattern {
                name: "it_is_worth_mentioning",
                regex: Regex::new(r"(?i)\bit is worth mentioning\b").unwrap(),
                severity: Severity::Medium,
                message: "AI hedge phrase: 'it is worth mentioning'",
            },
            AIPattern {
                name: "underscores_the_importance",
                regex: Regex::new(r"(?i)\bunderscore[s]? the importance\b").unwrap(),
                severity: Severity::Medium,
                message: "AI emphasis phrase: 'underscores the importance'",
            },
        ];

        TextAnalyzer { ai_patterns }
    }

    /// Analyze text content for AI-generated patterns
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = detect_text_type(path);
        let mut issues = Vec::new();
        
        // Count pattern occurrences and track which ones appear
        let mut pattern_counts = std::collections::HashMap::new();
        
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.ai_patterns {
                if pattern.regex.is_match(line) {
                    *pattern_counts.entry(pattern.name).or_insert(0) += 1;
                    
                    // Only report the first few occurrences to avoid spam
                    let count = pattern_counts[pattern.name];
                    if count <= 3 || (pattern.severity == Severity::High || pattern.severity == Severity::Critical) {
                        issues.push(Issue {
                            severity: pattern.severity.clone(),
                            message: if count > 1 {
                                format!("{} (occurrence #{} )", pattern.message, count)
                            } else {
                                pattern.message.to_string()
                            },
                            line: Some(line_num + 1),
                            rule: Some(pattern.name.to_string()),
                        });
                    }
                }
            }
        }
        
        // Check for excessive use of certain patterns (upgrade severity)
        for (pattern_name, count) in pattern_counts {
            if count >= 5
                && let Some(_pattern) = self.ai_patterns.iter().find(|p| p.name == pattern_name) {
                issues.push(Issue {
                    severity: Severity::Medium,
                    message: format!("Excessive use of AI pattern '{}' detected ({} times) - possible AI generation", pattern_name, count),
                    line: None,
                    rule: Some("excessive_ai_patterns".to_string()),
                });
            }
        }
        
        // Check for confidence without citations
        self.detect_unsourced_claims(content, &mut issues);
        
        AnalysisResult {
            path: path.to_path_buf(),
            file_type,
            issues,
            trust_score: 100, // Will be recalculated in lib.rs
        }
    }
    
    fn detect_unsourced_claims(&self, content: &str, issues: &mut Vec<Issue>) {
        // Patterns that indicate confident factual claims
        let claim_patterns = [
            r"(?i)\bstudies show\b",
            r"(?i)\bresearch indicates\b", 
            r"(?i)\bexperts agree\b",
            r"(?i)\bit is proven\b",
            r"(?i)\bscience shows\b",
            r"(?i)\bdata shows\b",
            r"(?i)\bevidence suggests\b",
            r"(?i)\baccording to research\b",
        ];
        
        // Citation patterns (things that would indicate sourcing)
        let citation_patterns = [
            r"\[[0-9]+\]",                    // [1], [23]
            r"\([^)]*[0-9]{4}[^)]*\)",       // (Author, 2023)
            r"https?://[^\s]+",              // URLs
            r"doi:[^\s]+",                   // DOI links
            r"(?i)according to [A-Z][a-z]+ ", // "according to Smith"
        ];
        
        let claim_regexes: Vec<Regex> = claim_patterns.iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();
            
        let citation_regexes: Vec<Regex> = citation_patterns.iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();
        
        // Check for claims without nearby citations
        for (line_num, line) in content.lines().enumerate() {
            for claim_regex in &claim_regexes {
                if claim_regex.is_match(line) {
                    // Check this line and surrounding lines for citations
                    let start_line = line_num.saturating_sub(1);
                    let end_line = std::cmp::min(line_num + 2, content.lines().count());
                    
                    let surrounding_text = content.lines()
                        .skip(start_line)
                        .take(end_line - start_line)
                        .collect::<Vec<_>>()
                        .join(" ");
                    
                    let has_citation = citation_regexes.iter()
                        .any(|c| c.is_match(&surrounding_text));
                    
                    if !has_citation {
                        issues.push(Issue {
                            severity: Severity::Medium,
                            message: "Confident factual claim without apparent citation or source".to_string(),
                            line: Some(line_num + 1),
                            rule: Some("unsourced_claims".to_string()),
                        });
                    }
                }
            }
        }
    }
}

fn detect_text_type(path: &Path) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension.to_lowercase().as_str() {
            "md" => FileType::Markdown,
            "txt" => FileType::Text,
            _ => FileType::Text,
        }
    } else {
        FileType::Text
    }
}