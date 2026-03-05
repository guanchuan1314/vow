use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use owo_colors::OwoColorize;
use crate::ProjectResults;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanHistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub total_files: usize,
    pub total_issues: usize,
    pub avg_score: u8,
    pub issues_by_severity: HashMap<String, usize>,
    pub issues_by_rule: HashMap<String, usize>,
    pub total_time_seconds: f32,
    pub files_skipped: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanHistory {
    pub version: String,
    pub scans: Vec<ScanHistoryEntry>,
}

impl ScanHistory {
    pub fn new() -> Self {
        ScanHistory {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scans: Vec::new(),
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(ScanHistory::new());
        }
        
        let content = fs::read_to_string(path)?;
        let history: ScanHistory = serde_json::from_str(&content)?;
        Ok(history)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure the parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn add_scan(&mut self, project_results: &ProjectResults) {
        // Extract issues by rule
        let mut issues_by_rule = HashMap::new();
        for file_result in &project_results.files {
            for issue in &file_result.issues {
                if let Some(rule) = &issue.rule {
                    *issues_by_rule.entry(rule.clone()).or_insert(0) += 1;
                }
            }
        }

        let entry = ScanHistoryEntry {
            timestamp: Utc::now(),
            total_files: project_results.summary.total_files,
            total_issues: project_results.summary.total_issues,
            avg_score: project_results.summary.avg_score,
            issues_by_severity: project_results.summary.issues_by_severity.clone(),
            issues_by_rule,
            total_time_seconds: project_results.summary.total_time_seconds,
            files_skipped: project_results.summary.files_skipped,
        };

        self.scans.push(entry);

        // Keep only the last 100 scans to prevent the file from growing too large
        if self.scans.len() > 100 {
            self.scans.drain(0..self.scans.len() - 100);
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StatsData {
    pub total_scans: usize,
    pub total_files_analyzed: usize,
    pub total_issues_found: usize,
    pub issues_by_severity: HashMap<String, usize>,
    pub top_rules: Vec<(String, usize)>,
    pub trend_last_n: Vec<TrendData>,
    pub fix_rate: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct TrendData {
    pub timestamp: DateTime<Utc>,
    pub total_issues: usize,
    pub avg_score: u8,
}

pub fn calculate_stats(history: &ScanHistory, last_n: usize) -> StatsData {
    let total_scans = history.scans.len();
    let total_files_analyzed = history.scans.iter().map(|s| s.total_files).sum();
    let total_issues_found = history.scans.iter().map(|s| s.total_issues).sum();

    // Aggregate issues by severity
    let mut issues_by_severity = HashMap::new();
    for scan in &history.scans {
        for (severity, count) in &scan.issues_by_severity {
            *issues_by_severity.entry(severity.clone()).or_insert(0) += count;
        }
    }

    // Aggregate issues by rule and get top 10
    let mut all_rules = HashMap::new();
    for scan in &history.scans {
        for (rule, count) in &scan.issues_by_rule {
            *all_rules.entry(rule.clone()).or_insert(0) += count;
        }
    }
    
    let mut top_rules: Vec<_> = all_rules.into_iter().collect();
    top_rules.sort_by(|a, b| b.1.cmp(&a.1));
    top_rules.truncate(10);

    // Calculate trend for last N scans
    let trend_data = if history.scans.len() > 0 {
        let start_index = if history.scans.len() > last_n {
            history.scans.len() - last_n
        } else {
            0
        };
        
        history.scans[start_index..]
            .iter()
            .map(|scan| TrendData {
                timestamp: scan.timestamp,
                total_issues: scan.total_issues,
                avg_score: scan.avg_score,
            })
            .collect()
    } else {
        Vec::new()
    };

    // Calculate fix rate (simple implementation: compare last scan with first scan)
    let fix_rate = if history.scans.len() >= 2 {
        let first_scan = &history.scans[0];
        let last_scan = &history.scans[history.scans.len() - 1];
        
        if first_scan.total_issues > 0 {
            let issues_reduced = if first_scan.total_issues > last_scan.total_issues {
                first_scan.total_issues - last_scan.total_issues
            } else {
                0
            };
            Some((issues_reduced as f64 / first_scan.total_issues as f64) * 100.0)
        } else {
            None
        }
    } else {
        None
    };

    StatsData {
        total_scans,
        total_files_analyzed,
        total_issues_found,
        issues_by_severity,
        top_rules,
        trend_last_n: trend_data,
        fix_rate,
    }
}

pub fn display_stats_dashboard(stats: &StatsData, json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(stats)?);
        return Ok(());
    }

    println!("\n{}", "=== VOW STATS DASHBOARD ===".bright_blue().bold());
    println!();

    // Overview section
    println!("{}", "📊 OVERVIEW".bright_cyan().bold());
    println!("  Total scans run: {}", stats.total_scans.to_string().bright_green());
    println!("  Total files analyzed: {}", stats.total_files_analyzed.to_string().bright_green());
    println!("  Total issues found: {}", stats.total_issues_found.to_string().bright_yellow());
    println!();

    // Issues by severity
    println!("{}", "🚨 ISSUES BY SEVERITY".bright_cyan().bold());
    let severity_order = ["critical", "high", "medium", "low"];
    for severity in severity_order {
        if let Some(&count) = stats.issues_by_severity.get(severity) {
            let bar = create_bar(count, stats.total_issues_found, 20);
            let severity_colored = match severity {
                "critical" => format!("{}", severity.bright_red().bold()),
                "high" => format!("{}", severity.bright_red()),
                "medium" => format!("{}", severity.yellow()),
                "low" => format!("{}", severity.blue()),
                _ => format!("{}", severity.white()),
            };
            println!("  {}: {} {}", severity_colored, count.to_string().bright_white(), bar);
        }
    }
    println!();

    // Top rules
    if !stats.top_rules.is_empty() {
        println!("{}", "🔍 TOP 10 RULES (Most Common Issues)".bright_cyan().bold());
        let max_count = stats.top_rules.first().map(|(_, c)| *c).unwrap_or(1);
        
        for (i, (rule, count)) in stats.top_rules.iter().enumerate() {
            let bar = create_bar(*count, max_count, 15);
            println!("  {}. {}: {} {}", 
                (i + 1).to_string().bright_white(), 
                rule.truncate_display(30).bright_yellow(),
                count.to_string().bright_white(), 
                bar
            );
        }
        println!();
    }

    // Fix rate
    if let Some(fix_rate) = stats.fix_rate {
        println!("{}", "🔧 FIX RATE".bright_cyan().bold());
        if fix_rate > 50.0 {
            println!("  {:.1}% issues resolved since first scan", format!("{}", format!("{:.1}%", fix_rate).bright_green()));
        } else if fix_rate > 20.0 {
            println!("  {:.1}% issues resolved since first scan", format!("{}", format!("{:.1}%", fix_rate).yellow()));
        } else {
            println!("  {:.1}% issues resolved since first scan", format!("{}", format!("{:.1}%", fix_rate).bright_red()));
        }
        println!();
    }

    // Trend
    if !stats.trend_last_n.is_empty() {
        println!("{}", "📈 RECENT TREND (Last 10 Scans)".bright_cyan().bold());
        if stats.trend_last_n.len() >= 2 {
            let first = &stats.trend_last_n[0];
            let last = &stats.trend_last_n[stats.trend_last_n.len() - 1];
            
            let issues_change = last.total_issues as i32 - first.total_issues as i32;
            let score_change = last.avg_score as i32 - first.avg_score as i32;
            
            let trend_icon = if issues_change < 0 && score_change > 0 {
                format!("{}", "📈 IMPROVING".bright_green().bold())
            } else if issues_change > 0 && score_change < 0 {
                format!("{}", "📉 WORSENING".bright_red().bold())
            } else {
                format!("{}", "➡️  STABLE".yellow().bold())
            };
            
            println!("  Trend: {}", trend_icon);
            println!("  Issues change: {}", format_change(issues_change));
            println!("  Score change: {}", format_change(score_change));
            
            // Simple ASCII chart of last few scans
            println!("\n  Recent issues (last {} scans):", stats.trend_last_n.len().min(10));
            display_simple_chart(&stats.trend_last_n);
        }
        println!();
    }

    Ok(())
}

fn create_bar(value: usize, max_value: usize, bar_length: usize) -> String {
    if max_value == 0 {
        return " ".repeat(bar_length);
    }
    
    let filled_length = (value as f64 / max_value as f64 * bar_length as f64).round() as usize;
    let filled = "█".repeat(filled_length);
    let empty = "░".repeat(bar_length.saturating_sub(filled_length));
    format!("[{}{}]", filled.bright_white(), empty.dimmed())
}

fn format_change(change: i32) -> String {
    if change > 0 {
        format!("{}", format!("+{}", change).bright_red())
    } else if change < 0 {
        format!("{}", change.to_string().bright_green())
    } else {
        format!("{}", "0".white())
    }
}

fn display_simple_chart(trend_data: &[TrendData]) {
    let max_issues = trend_data.iter().map(|t| t.total_issues).max().unwrap_or(1);
    let chart_height = 5;
    
    for i in (0..chart_height).rev() {
        print!("    ");
        for data_point in trend_data.iter().take(10) {
            let normalized = (data_point.total_issues as f64 / max_issues as f64) * (chart_height as f64);
            if normalized >= i as f64 {
                print!("{}", "▄".bright_yellow());
            } else {
                print!(" ");
            }
        }
        println!();
    }
    
    print!("    ");
    for _ in 0..trend_data.len().min(10) {
        print!("─");
    }
    println!();
}

trait TruncateDisplay {
    fn truncate_display(&self, max_len: usize) -> String;
}

impl TruncateDisplay for str {
    fn truncate_display(&self, max_len: usize) -> String {
        if self.len() <= max_len {
            self.to_string()
        } else {
            format!("{}...", &self[0..max_len.saturating_sub(3)])
        }
    }
}

/// Save scan results to history
pub fn save_scan_to_history(project_results: &ProjectResults) -> Result<(), Box<dyn std::error::Error>> {
    let history_path = Path::new(".vow/history.json");
    
    let mut history = ScanHistory::load_from_file(history_path)?;
    history.add_scan(project_results);
    history.save_to_file(history_path)?;
    
    Ok(())
}

/// Display stats dashboard by reading from history
pub fn display_stats_from_history(json_output: bool, last_n_scans: usize) -> Result<(), Box<dyn std::error::Error>> {
    let history_path = Path::new(".vow/history.json");
    let history = ScanHistory::load_from_file(history_path)?;
    
    if history.scans.is_empty() {
        println!("No scan history found. Run some scans first with 'vow check' to generate stats.");
        return Ok(());
    }
    
    let stats = calculate_stats(&history, last_n_scans);
    display_stats_dashboard(&stats, json_output)?;
    
    Ok(())
}