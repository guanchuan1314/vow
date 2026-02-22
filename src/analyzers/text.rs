use std::path::PathBuf;
use crate::{AnalysisResult, Issue, Severity, FileType};

/// Text analyzer for detecting issues in text content
pub struct TextAnalyzer;

impl TextAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    /// Analyze text content for potential issues
    pub fn analyze(&self, path: &PathBuf, content: &str) -> AnalysisResult {
        let mut issues = Vec::new();
        
        // Check for potential hallucinated content markers
        if content.contains("API_KEY") || content.contains("SECRET_KEY") {
            issues.push(Issue {
                severity: Severity::Medium,
                message: "Potential hardcoded credentials detected".to_string(),
                line: None,
            });
        }
        
        // Check for common AI hallucination patterns
        if content.contains("As an AI") || content.contains("I don't have access") {
            issues.push(Issue {
                severity: Severity::Low,
                message: "AI-generated content markers detected".to_string(),
                line: None,
            });
        }
        
        // Check for placeholder text
        if content.contains("TODO") || content.contains("FIXME") {
            issues.push(Issue {
                severity: Severity::Low,
                message: "Incomplete content markers found".to_string(),
                line: None,
            });
        }
        
        AnalysisResult {
            path: path.clone(),
            file_type: FileType::Text,
            issues,
        }
    }
}