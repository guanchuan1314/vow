pub mod port_scanner;
pub mod security_evaluator;

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_open: bool,
    pub service: Option<ServiceInfo>,
    pub security_status: SecurityStatus,
    pub risk_level: RiskLevel,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityStatus {
    Secure,
    Insecure,
    Unknown,
    RequiresInvestigation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortScanResults {
    pub target: String,
    pub scanned_ports: Vec<u16>,
    pub scan_results: Vec<ScanResult>,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub secure_ports: usize,
    pub insecure_ports: usize,
    pub unknown_ports: usize,
    pub critical_issues: usize,
    pub high_risk_issues: usize,
    pub medium_risk_issues: usize,
    pub low_risk_issues: usize,
}

impl RiskLevel {
    pub fn score_impact(&self) -> u8 {
        match self {
            RiskLevel::Critical => 30,
            RiskLevel::High => 20,
            RiskLevel::Medium => 10,
            RiskLevel::Low => 5,
        }
    }
}

pub fn calculate_security_score(results: &[ScanResult]) -> u8 {
    let mut score = 100u8;
    
    for result in results {
        if result.is_open {
            match result.security_status {
                SecurityStatus::Insecure => {
                    score = score.saturating_sub(result.risk_level.score_impact());
                }
                SecurityStatus::RequiresInvestigation => {
                    score = score.saturating_sub(result.risk_level.score_impact() / 2);
                }
                _ => {}
            }
        }
    }
    
    score
}