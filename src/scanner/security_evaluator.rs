use super::{ServiceInfo, SecurityStatus, RiskLevel};

pub struct SecurityEvaluator {
    // Security baselines for common ports
}

impl SecurityEvaluator {
    pub fn new() -> Self {
        Self {}
    }
    
    /// Evaluate the security posture of an open port
    pub async fn evaluate_port_security(
        &self,
        port: u16,
        _service: &Option<ServiceInfo>,
    ) -> (SecurityStatus, RiskLevel, Option<String>) {
        match port {
            // SSH - Generally secure if properly configured
            22 => (
                SecurityStatus::RequiresInvestigation,
                RiskLevel::Medium,
                Some("Ensure SSH is configured with key-based authentication, disable password auth, and limit user access. Consider changing default port.".to_string())
            ),
            
            // Telnet - Highly insecure, transmits in plaintext
            23 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("Telnet transmits credentials and data in plaintext. Replace with SSH immediately.".to_string())
            ),
            
            // FTP - Often insecure, depends on configuration
            21 => (
                SecurityStatus::Insecure,
                RiskLevel::High,
                Some("FTP often transmits credentials in plaintext. Use SFTP or FTPS instead. If FTP is required, ensure it's properly secured with TLS.".to_string())
            ),
            
            // SMTP - Requires proper configuration
            25 => (
                SecurityStatus::RequiresInvestigation,
                RiskLevel::Medium,
                Some("Ensure SMTP requires authentication and uses TLS encryption. Monitor for open relay configuration.".to_string())
            ),
            
            // DNS - Usually safe if properly configured
            53 => (
                SecurityStatus::RequiresInvestigation,
                RiskLevel::Low,
                Some("Ensure DNS server is not configured as an open resolver and is protected against DNS amplification attacks.".to_string())
            ),
            
            // HTTP - Should redirect to HTTPS
            80 => (
                SecurityStatus::Insecure,
                RiskLevel::Medium,
                Some("HTTP transmits data in plaintext. Ensure all HTTP requests redirect to HTTPS (port 443).".to_string())
            ),
            
            // HTTPS - Generally secure
            443 => (
                SecurityStatus::Secure,
                RiskLevel::Low,
                Some("HTTPS is secure. Ensure TLS certificate is valid and up-to-date, and strong cipher suites are used.".to_string())
            ),
            
            // POP3 - Insecure without TLS
            110 => (
                SecurityStatus::Insecure,
                RiskLevel::High,
                Some("POP3 transmits credentials and emails in plaintext. Use POP3S (port 995) instead.".to_string())
            ),
            
            // IMAP - Insecure without TLS
            143 => (
                SecurityStatus::Insecure,
                RiskLevel::High,
                Some("IMAP transmits credentials and emails in plaintext. Use IMAPS (port 993) instead.".to_string())
            ),
            
            // IMAPS - Secure
            993 => (
                SecurityStatus::Secure,
                RiskLevel::Low,
                Some("IMAPS uses TLS encryption. Ensure strong authentication and monitor for unauthorized access.".to_string())
            ),
            
            // POP3S - Secure
            995 => (
                SecurityStatus::Secure,
                RiskLevel::Low,
                Some("POP3S uses TLS encryption. Ensure strong authentication and monitor for unauthorized access.".to_string())
            ),
            
            // SQL Server - High risk if exposed
            1433 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("SQL Server should not be directly exposed to the internet. Use VPN, firewall rules, or tunnel connections. Ensure strong authentication and encryption.".to_string())
            ),
            
            // MySQL - High risk if exposed
            3306 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("MySQL should not be directly exposed to the internet. Use VPN, firewall rules, or tunnel connections. Ensure strong authentication and SSL/TLS.".to_string())
            ),
            
            // RDP - High risk if exposed
            3389 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("RDP should not be directly exposed to the internet due to frequent attacks. Use VPN, change default port, enable NLA, and require strong authentication.".to_string())
            ),
            
            // PostgreSQL - High risk if exposed
            5432 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("PostgreSQL should not be directly exposed to the internet. Use VPN, firewall rules, or tunnel connections. Ensure strong authentication and SSL encryption.".to_string())
            ),
            
            // CouchDB - Moderate risk
            5984 => (
                SecurityStatus::Insecure,
                RiskLevel::High,
                Some("CouchDB should be secured with proper authentication and HTTPS. Avoid exposing admin interfaces to the internet.".to_string())
            ),
            
            // Redis - High risk if exposed
            6379 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("Redis should not be directly exposed to the internet. It lacks built-in encryption and has weak authentication. Use VPN or tunneling.".to_string())
            ),
            
            // MongoDB - High risk if exposed  
            27017 => (
                SecurityStatus::Insecure,
                RiskLevel::Critical,
                Some("MongoDB should not be directly exposed to the internet. Ensure authentication is enabled, use TLS/SSL, and restrict network access.".to_string())
            ),
            
            // Common web development ports
            3000 | 4000 | 5000 | 8000 | 8080 | 8888 => (
                SecurityStatus::Insecure,
                RiskLevel::Medium,
                Some("Development/testing ports should not be exposed in production. These often lack security features and may expose sensitive information.".to_string())
            ),
            
            // High-numbered ports (often custom services)
            port if port > 10000 => (
                SecurityStatus::RequiresInvestigation,
                RiskLevel::Medium,
                Some("High-numbered port detected. Verify this is an intentionally exposed service and ensure it has proper security controls.".to_string())
            ),
            
            // Well-known privileged ports
            port if port < 1024 => (
                SecurityStatus::RequiresInvestigation,
                RiskLevel::Medium,
                Some("Privileged port detected. Ensure this service is properly secured and only necessary services are exposed.".to_string())
            ),
            
            // Other ports
            _ => (
                SecurityStatus::Unknown,
                RiskLevel::Low,
                Some("Unknown service detected. Investigate to ensure it's authorized and properly secured.".to_string())
            ),
        }
    }
    
    /// Get security recommendations for a specific service
    pub fn get_general_security_recommendations(&self) -> Vec<String> {
        vec![
            "Implement a firewall to block unnecessary ports".to_string(),
            "Use strong, unique passwords for all services".to_string(),
            "Enable two-factor authentication where possible".to_string(),
            "Keep all services and software up to date".to_string(),
            "Monitor logs for suspicious activity".to_string(),
            "Use TLS/SSL encryption for all network communications".to_string(),
            "Follow the principle of least privilege for user accounts".to_string(),
            "Regularly audit exposed services and close unnecessary ones".to_string(),
            "Consider using a VPN for administrative access".to_string(),
            "Implement intrusion detection and prevention systems".to_string(),
        ]
    }
    
    /// Calculate overall security assessment
    pub fn assess_overall_security(&self, scan_results: &[super::ScanResult]) -> (SecurityStatus, String) {
        let critical_issues = scan_results.iter().filter(|r| r.risk_level == RiskLevel::Critical && r.is_open).count();
        let high_issues = scan_results.iter().filter(|r| r.risk_level == RiskLevel::High && r.is_open).count();
        let insecure_ports = scan_results.iter().filter(|r| r.security_status == SecurityStatus::Insecure && r.is_open).count();
        
        let total_open = scan_results.iter().filter(|r| r.is_open).count();
        
        if critical_issues > 0 {
            (
                SecurityStatus::Insecure,
                format!(
                    "CRITICAL: {} critical security issues found. {} high-risk issues. Immediate action required.",
                    critical_issues, high_issues
                )
            )
        } else if high_issues > 2 {
            (
                SecurityStatus::Insecure,
                format!(
                    "HIGH RISK: {} high-risk security issues found. Review and secure exposed services immediately.",
                    high_issues
                )
            )
        } else if insecure_ports > total_open / 2 {
            (
                SecurityStatus::Insecure,
                format!(
                    "MODERATE RISK: {}/{} open ports have security concerns. Review and improve security posture.",
                    insecure_ports, total_open
                )
            )
        } else if insecure_ports > 0 || high_issues > 0 {
            (
                SecurityStatus::RequiresInvestigation,
                format!(
                    "NEEDS REVIEW: {} ports require security investigation. Address identified issues.",
                    insecure_ports + high_issues
                )
            )
        } else {
            (
                SecurityStatus::Secure,
                "Security posture appears good. Continue monitoring and maintaining current security practices.".to_string()
            )
        }
    }
}