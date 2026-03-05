use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use futures::future::join_all;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use super::{ScanResult, ServiceInfo, SecurityStatus, RiskLevel, PortScanResults, ScanSummary};
use super::security_evaluator::SecurityEvaluator;

pub struct PortScanner {
    timeout: Duration,
    concurrency: usize,
    evaluator: SecurityEvaluator,
}

impl PortScanner {
    pub fn new(timeout_ms: u64, concurrency: usize) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            concurrency,
            evaluator: SecurityEvaluator::new(),
        }
    }
    
    /// Parse a target string (IP, hostname, or CIDR range)
    pub async fn resolve_targets(&self, target: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
        // Check if it's an IP address
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        
        // Check if it's a CIDR range
        if target.contains('/') {
            return self.parse_cidr_range(target);
        }
        
        // Try to resolve as hostname
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        
        match resolver.lookup_ip(target).await {
            Ok(lookup) => Ok(lookup.iter().collect()),
            Err(_) => Err(format!("Could not resolve hostname: {}", target).into()),
        }
    }
    
    /// Parse CIDR range (simplified implementation)
    fn parse_cidr_range(&self, cidr: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".into());
        }
        
        let base_ip: IpAddr = parts[0].parse()?;
        let prefix_len: u8 = parts[1].parse()?;
        
        // For simplicity, limit to small subnets to avoid overwhelming scans
        if prefix_len < 24 {
            return Err("CIDR ranges larger than /24 are not supported for safety".into());
        }
        
        match base_ip {
            IpAddr::V4(ipv4) => {
                let mut ips = Vec::new();
                let base = u32::from(ipv4);
                let mask = !(0xFFFFFFFFu32 >> prefix_len);
                let network = base & mask;
                let host_bits = 32 - prefix_len;
                let max_hosts = (1u32 << host_bits) - 2; // Exclude network and broadcast
                
                for i in 1..=max_hosts.min(254) { // Limit to reasonable range
                    let ip = std::net::Ipv4Addr::from(network + i);
                    ips.push(IpAddr::V4(ip));
                }
                Ok(ips)
            }
            IpAddr::V6(_) => Err("IPv6 CIDR ranges not yet supported".into()),
        }
    }
    
    /// Parse port specification (e.g., "80", "1-1000", "22,80,443")
    pub fn parse_ports(&self, port_spec: &str) -> Result<Vec<u16>, Box<dyn std::error::Error + Send + Sync>> {
        let mut ports = Vec::new();
        
        for part in port_spec.split(',') {
            let part = part.trim();
            
            if part.contains('-') {
                // Range specification
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(format!("Invalid port range: {}", part).into());
                }
                
                let start: u16 = range_parts[0].parse()?;
                let end: u16 = range_parts[1].parse()?;
                
                if start > end {
                    return Err(format!("Invalid port range: start {} > end {}", start, end).into());
                }
                
                // Limit range size for safety
                if end - start > 10000 {
                    return Err("Port range too large (max 10000 ports)".into());
                }
                
                for port in start..=end {
                    ports.push(port);
                }
            } else {
                // Single port
                let port: u16 = part.parse()?;
                ports.push(port);
            }
        }
        
        Ok(ports)
    }
    
    /// Scan multiple targets and ports
    pub async fn scan(&self, targets: Vec<IpAddr>, ports: Vec<u16>) -> Result<PortScanResults, Box<dyn std::error::Error + Send + Sync>> {
        let mut all_results = Vec::new();
        
        for target in &targets {
            let target_results = self.scan_target(*target, &ports).await?;
            all_results.extend(target_results);
        }
        
        let summary = self.calculate_summary(&all_results, &ports);
        
        Ok(PortScanResults {
            target: if targets.len() == 1 {
                targets[0].to_string()
            } else {
                format!("{} targets", targets.len())
            },
            scanned_ports: ports,
            scan_results: all_results,
            summary,
        })
    }
    
    /// Scan a single target
    async fn scan_target(&self, target: IpAddr, ports: &[u16]) -> Result<Vec<ScanResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut tasks = Vec::new();
        
        // Create batches to limit concurrency
        for chunk in ports.chunks(self.concurrency) {
            let chunk_tasks: Vec<_> = chunk
                .iter()
                .map(|&port| self.scan_port(target, port))
                .collect();
            
            let chunk_results = join_all(chunk_tasks).await;
            
            for result in chunk_results {
                tasks.push(result?);
            }
        }
        
        Ok(tasks)
    }
    
    /// Scan a single port on a target
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
        let socket_addr = SocketAddr::new(target, port);
        
        let is_open = match timeout(self.timeout, TcpStream::connect(socket_addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        };
        
        let (service, security_status, risk_level, recommendation) = if is_open {
            let service_info = self.detect_service(port).await;
            let (status, risk, rec) = self.evaluator.evaluate_port_security(port, &service_info).await;
            (service_info, status, risk, rec)
        } else {
            (None, SecurityStatus::Unknown, RiskLevel::Low, None)
        };
        
        Ok(ScanResult {
            target,
            port,
            is_open,
            service,
            security_status,
            risk_level,
            recommendation,
        })
    }
    
    /// Detect service running on a port
    async fn detect_service(&self, port: u16) -> Option<ServiceInfo> {
        // Basic service detection based on common port assignments
        let (name, description) = match port {
            21 => ("FTP", "File Transfer Protocol"),
            22 => ("SSH", "Secure Shell"),
            23 => ("Telnet", "Telnet remote login"),
            25 => ("SMTP", "Simple Mail Transfer Protocol"),
            53 => ("DNS", "Domain Name System"),
            80 => ("HTTP", "HyperText Transfer Protocol"),
            110 => ("POP3", "Post Office Protocol v3"),
            143 => ("IMAP", "Internet Message Access Protocol"),
            443 => ("HTTPS", "HTTP over TLS/SSL"),
            993 => ("IMAPS", "IMAP over TLS/SSL"),
            995 => ("POP3S", "POP3 over TLS/SSL"),
            1433 => ("MSSQL", "Microsoft SQL Server"),
            3306 => ("MySQL", "MySQL Database"),
            3389 => ("RDP", "Remote Desktop Protocol"),
            5432 => ("PostgreSQL", "PostgreSQL Database"),
            5984 => ("CouchDB", "CouchDB Database"),
            6379 => ("Redis", "Redis Database"),
            27017 => ("MongoDB", "MongoDB Database"),
            _ => ("Unknown", "Unknown service"),
        };
        
        if name != "Unknown" {
            Some(ServiceInfo {
                name: name.to_string(),
                description: description.to_string(),
                banner: None, // TODO: Implement banner grabbing
            })
        } else {
            None
        }
    }
    
    /// Calculate scan summary
    fn calculate_summary(&self, results: &[ScanResult], ports: &[u16]) -> ScanSummary {
        let open_ports = results.iter().filter(|r| r.is_open).count();
        let secure_ports = results.iter().filter(|r| r.is_open && r.security_status == SecurityStatus::Secure).count();
        let insecure_ports = results.iter().filter(|r| r.is_open && r.security_status == SecurityStatus::Insecure).count();
        let unknown_ports = results.iter().filter(|r| r.is_open && r.security_status == SecurityStatus::Unknown).count();
        
        let critical_issues = results.iter().filter(|r| r.is_open && r.risk_level == RiskLevel::Critical).count();
        let high_risk_issues = results.iter().filter(|r| r.is_open && r.risk_level == RiskLevel::High).count();
        let medium_risk_issues = results.iter().filter(|r| r.is_open && r.risk_level == RiskLevel::Medium).count();
        let low_risk_issues = results.iter().filter(|r| r.is_open && r.risk_level == RiskLevel::Low).count();
        
        ScanSummary {
            total_ports_scanned: ports.len(),
            open_ports,
            secure_ports,
            insecure_ports,
            unknown_ports,
            critical_issues,
            high_risk_issues,
            medium_risk_issues,
            low_risk_issues,
        }
    }
}