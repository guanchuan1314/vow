use std::path::Path;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;

/// Text analyzer for detecting AI-generated content patterns
pub struct TextAnalyzer {
    ai_patterns: Vec<AIPattern>,
    phrase_patterns: Vec<PhrasePattern>,
    sentence_analyzer: SentenceAnalyzer,
}

struct AIPattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    message: &'static str,
}

struct PhrasePattern {
    name: &'static str,
    phrases: Vec<&'static str>,
    severity: Severity,
    message: &'static str,
    confidence_boost: u8,
}

#[derive(Debug)]
struct SentenceAnalysis {
    sentence_count: usize,
    avg_sentence_length: f32,
    length_variance: f32,
    hedging_phrases_count: usize,
    confidence_score: u8,
}

struct SentenceAnalyzer {
    hedging_patterns: Vec<&'static str>,
}

impl Default for TextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SentenceAnalyzer {
    fn new() -> Self {
        SentenceAnalyzer {
            hedging_patterns: vec![
                // Original patterns
                "it's important to note",
                "it's worth mentioning", 
                "it should be noted",
                "it's crucial to understand",
                "it's essential to realize",
                "one might argue",
                "it could be said",
                "in many cases",
                "generally speaking",
                "broadly speaking",
                "arguably",
                "presumably",
                "conceivably",
                "potentially",
                "theoretically",
                "hypothetically",
                "allegedly",
                // Enhanced hedging phrases - common AI patterns
                "in this article we will",
                "let's dive in", 
                "without further ado",
                "in conclusion",
                "it's important to understand",
                "it's worth noting that",
                "it's crucial to recognize",
                "one should note",
                "it bears mentioning",
                "it's particularly important",
                "it must be emphasized",
                "we should consider",
                "let's explore",
                "let's examine",
                "let's take a look",
            ],
        }
    }

    fn analyze_sentences(&self, content: &str) -> SentenceAnalysis {
        let sentences: Vec<&str> = content
            .split(&['.', '!', '?'][..])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.len() > 10) // Filter out short fragments
            .collect();

        let sentence_count = sentences.len();
        
        if sentence_count == 0 {
            return SentenceAnalysis {
                sentence_count: 0,
                avg_sentence_length: 0.0,
                length_variance: 0.0,
                hedging_phrases_count: 0,
                confidence_score: 0,
            };
        }

        // Enhanced sentence length statistics with proper standard deviation
        let lengths: Vec<f32> = sentences.iter().map(|s| s.len() as f32).collect();
        let avg_length = lengths.iter().sum::<f32>() / lengths.len() as f32;
        
        // Calculate variance and standard deviation (measure of sentence length uniformity)
        let variance = lengths.iter()
            .map(|&x| (x - avg_length).powi(2))
            .sum::<f32>() / lengths.len() as f32;
        let std_dev = variance.sqrt();

        // Count hedging phrases with case-insensitive matching
        let content_lower = content.to_lowercase();
        let hedging_count = self.hedging_patterns.iter()
            .map(|pattern| content_lower.matches(pattern).count())
            .sum::<usize>();

        // Enhanced AI confidence scoring system with weighted signals
        let mut confidence = 0u8;
        
        // Signal 1: Sentence length uniformity (AI produces very uniform sentence lengths)
        // Low standard deviation indicates uniformity
        if sentence_count > 5 {
            let coefficient_of_variation = std_dev / avg_length;
            if coefficient_of_variation < 0.2 {
                confidence += 30; // Very uniform sentences - strong AI signal
            } else if coefficient_of_variation < 0.35 {
                confidence += 20; // Somewhat uniform sentences
            } else if coefficient_of_variation < 0.5 {
                confidence += 10; // Slightly uniform
            }
        }
        
        // Signal 2: AI tends toward specific sentence length ranges
        if sentence_count > 3 {
            // AI often produces sentences in the "sweet spot" of 80-140 characters
            if avg_length > 80.0 && avg_length < 140.0 {
                confidence += 15;
            }
            // Very short or very long average sentences are less AI-like
            if avg_length < 50.0 || avg_length > 200.0 {
                confidence = confidence.saturating_sub(10);
            }
        }
        
        // Signal 3: Hedging phrases (weighted scoring)
        let hedging_ratio = hedging_count as f32 / sentence_count as f32;
        if hedging_ratio > 0.4 {
            confidence += 25; // Excessive hedging - very strong AI signal
        } else if hedging_ratio > 0.2 {
            confidence += 15; // High hedging frequency
        } else if hedging_ratio > 0.1 {
            confidence += 10; // Moderate hedging
        } else if hedging_ratio > 0.05 {
            confidence += 5; // Some hedging
        }

        // Signal 4: Sentence count patterns (AI tends to produce predictable paragraph lengths)
        if sentence_count >= 15 && sentence_count <= 25 {
            confidence += 5; // Typical AI article length
        }

        SentenceAnalysis {
            sentence_count,
            avg_sentence_length: avg_length,
            length_variance: variance,
            hedging_phrases_count: hedging_count,
            confidence_score: confidence.min(100), // Cap at 100%
        }
    }
}

impl TextAnalyzer {
    /// Analyze transition word density for AI detection
    fn analyze_transition_density(&self, content: &str) -> (usize, u8) {
        let formal_transitions = vec![
            "furthermore", "moreover", "additionally", "consequently", "nevertheless",
            "therefore", "thus", "hence", "accordingly", "subsequently",
            "in addition", "in contrast", "on the contrary", "as a result",
            "in conclusion", "to summarize", "in summary", "overall"
        ];
        
        let content_lower = content.to_lowercase();
        let word_count = content.split_whitespace().count();
        let sentence_count = content.matches(&['.', '!', '?'][..]).count();
        
        let transition_count: usize = formal_transitions.iter()
            .map(|transition| content_lower.matches(transition).count())
            .sum();
        
        // Calculate transition density and confidence score
        let mut confidence = 0u8;
        
        if word_count > 100 {
            let transition_density = transition_count as f32 / word_count as f32;
            
            // High transition density is an AI tell
            if transition_density > 0.03 { // More than 3% transition words
                confidence += 25;
            } else if transition_density > 0.02 {
                confidence += 15;
            } else if transition_density > 0.015 {
                confidence += 10;
            }
        }
        
        // Check for repetitive use of same transition
        for transition in &formal_transitions {
            let occurrences = content_lower.matches(transition).count();
            if occurrences >= 3 && sentence_count > 10 {
                confidence += 15; // Repetitive transition usage
                break; // Only count once per analysis
            }
        }
        
        (transition_count, confidence)
    }

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
                name: "consequently",
                regex: Regex::new(r"(?i)\bconsequently\b").unwrap(),
                severity: Severity::Low,
                message: "Formal transition word often overused by AI: 'consequently'",
            },
            AIPattern {
                name: "nevertheless",
                regex: Regex::new(r"(?i)\bnevertheless\b").unwrap(),
                severity: Severity::Low,
                message: "Formal transition word often overused by AI: 'nevertheless'",
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

        let phrase_patterns = vec![
            PhrasePattern {
                name: "ai_transition_phrases",
                phrases: vec![
                    "moving forward", "that being said", "on the other hand",
                    "having said that", "be that as it may", "with that in mind",
                    "all things considered", "in light of this", "taking into account",
                    "in this context", "from this perspective", "with this in mind"
                ],
                severity: Severity::Low,
                message: "AI-favored transition phrases detected",
                confidence_boost: 5,
            },
            PhrasePattern {
                name: "overused_transitions",
                phrases: vec![
                    "furthermore", "moreover", "additionally", "consequently", "nevertheless",
                    "therefore", "thus", "hence", "accordingly", "subsequently",
                    "in addition", "in contrast", "on the contrary", "as a result"
                ],
                severity: Severity::Low,
                message: "Overused formal transitions (AI tendency)",
                confidence_boost: 8,
            },
            PhrasePattern {
                name: "ai_emphasis_phrases", 
                phrases: vec![
                    "it cannot be overstated", "it bears repeating", 
                    "it's worth emphasizing", "it's particularly noteworthy",
                    "it's especially important", "one cannot ignore",
                    "it should be emphasized", "it's critically important"
                ],
                severity: Severity::Medium,
                message: "AI emphasis patterns detected",
                confidence_boost: 10,
            },
            PhrasePattern {
                name: "ai_qualification_phrases",
                phrases: vec![
                    "in most cases", "in many instances", "to a large extent",
                    "for the most part", "by and large", "in the majority of cases",
                    "more often than not", "in general terms", "as a general rule"
                ],
                severity: Severity::Low,
                message: "AI qualification language detected",
                confidence_boost: 7,
            },
            PhrasePattern {
                name: "ai_complexity_phrases",
                phrases: vec![
                    "myriad of factors", "multifaceted approach", "holistic perspective",
                    "comprehensive understanding", "nuanced approach", "intricate details",
                    "complex interplay", "sophisticated analysis", "in-depth exploration"
                ],
                severity: Severity::Medium,
                message: "AI complexity language patterns detected",
                confidence_boost: 12,
            },
        ];

        TextAnalyzer { 
            ai_patterns,
            phrase_patterns,
            sentence_analyzer: SentenceAnalyzer::new(),
        }
    }

    /// Analyze text content for AI-generated patterns
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = detect_text_type(path);
        let mut issues = Vec::new();
        let mut total_confidence_score = 0u8;
        
        // Count pattern occurrences and track which ones appear
        let mut pattern_counts = std::collections::HashMap::new();
        
        // Enhanced regex pattern analysis
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

        // Enhanced phrase pattern analysis
        for phrase_pattern in &self.phrase_patterns {
            let mut phrase_matches = 0;
            let content_lower = content.to_lowercase();
            
            for phrase in &phrase_pattern.phrases {
                phrase_matches += content_lower.matches(phrase).count();
            }
            
            if phrase_matches > 0 {
                total_confidence_score = total_confidence_score.saturating_add(
                    phrase_pattern.confidence_boost.saturating_mul(phrase_matches.min(3) as u8)
                );
                
                issues.push(Issue {
                    severity: phrase_pattern.severity.clone(),
                    message: format!("{} ({} instances, confidence +{})", 
                                   phrase_pattern.message, 
                                   phrase_matches,
                                   phrase_pattern.confidence_boost * phrase_matches.min(3) as u8),
                    line: None,
                    rule: Some(phrase_pattern.name.to_string()),
                });
            }
        }

        // Enhanced sentence structure analysis
        let sentence_analysis = self.sentence_analyzer.analyze_sentences(content);
        total_confidence_score = total_confidence_score.saturating_add(sentence_analysis.confidence_score);
        
        // Enhanced transition density analysis
        let (transition_count, transition_confidence) = self.analyze_transition_density(content);
        total_confidence_score = total_confidence_score.saturating_add(transition_confidence);
        
        // Report sentence analysis findings
        if sentence_analysis.confidence_score > 15 {
            let std_dev = sentence_analysis.length_variance.sqrt();
            let coefficient_of_variation = if sentence_analysis.avg_sentence_length > 0.0 {
                std_dev / sentence_analysis.avg_sentence_length
            } else {
                0.0
            };
            
            issues.push(Issue {
                severity: if sentence_analysis.confidence_score > 35 { Severity::Medium } else { Severity::Low },
                message: format!(
                    "Suspicious sentence uniformity: avg_length={:.1}, std_dev={:.1}, uniformity_coeff={:.3}, hedging_count={}, confidence=+{}%",
                    sentence_analysis.avg_sentence_length,
                    std_dev,
                    coefficient_of_variation,
                    sentence_analysis.hedging_phrases_count,
                    sentence_analysis.confidence_score
                ),
                line: None,
                rule: Some("sentence_uniformity_analysis".to_string()),
            });
        }
        
        // Report transition analysis findings
        if transition_confidence > 10 {
            issues.push(Issue {
                severity: if transition_confidence > 20 { Severity::Medium } else { Severity::Low },
                message: format!(
                    "Excessive formal transitions detected: {} transitions, confidence=+{}%", 
                    transition_count, 
                    transition_confidence
                ),
                line: None,
                rule: Some("transition_density_analysis".to_string()),
            });
        }
        
        // Check for excessive use of certain patterns (upgrade severity)
        for (pattern_name, count) in pattern_counts {
            if count >= 5
                && let Some(_pattern) = self.ai_patterns.iter().find(|p| p.name == pattern_name) {
                total_confidence_score = total_confidence_score.saturating_add(15);
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
        
        // Enhanced overall confidence assessment with detailed breakdown
        let final_confidence = total_confidence_score.min(100);
        
        if final_confidence > 25 {
            let severity = match final_confidence {
                75..=100 => Severity::High,
                50..=74 => Severity::Medium,
                _ => Severity::Low,
            };
            
            let confidence_description = match final_confidence {
                75..=100 => "Very High",
                60..=74 => "High", 
                45..=59 => "Moderate-High",
                30..=44 => "Moderate",
                _ => "Low-Moderate",
            };
            
            issues.push(Issue {
                severity,
                message: format!(
                    "{} AI generation confidence: {}% - Detected: sentence uniformity (+{}%), transitions (+{}%), phrases (+{}%)", 
                    confidence_description,
                    final_confidence,
                    sentence_analysis.confidence_score,
                    transition_confidence,
                    total_confidence_score.saturating_sub(sentence_analysis.confidence_score).saturating_sub(transition_confidence)
                ),
                line: None,
                rule: Some("ai_confidence_assessment".to_string()),
            });
        }
        
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