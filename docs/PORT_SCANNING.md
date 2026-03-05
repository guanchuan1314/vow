# Port Scanning & Security Analysis

Vow now includes a built-in port scanner that can identify open ports and evaluate them against security standards.

## Features

- **Fast concurrent scanning**: Configurable concurrency for efficient scanning
- **Security evaluation**: Each open port is evaluated against security baselines
- **Risk assessment**: Ports are classified by risk level (Critical, High, Medium, Low)
- **Comprehensive reporting**: Detailed security recommendations for each service
- **Multiple output formats**: Terminal (colorized) and JSON output
- **Flexible targeting**: Support for IP addresses, hostnames, and CIDR ranges

## Usage

### Basic Port Scan

```bash
# Scan common ports on localhost
vow scan 127.0.0.1

# Scan specific ports
vow scan example.com --ports 22,80,443,8080

# Scan a port range
vow scan 192.168.1.1 --ports 1-1000

# Scan with higher concurrency
vow scan target.host --ports 1-65535 --concurrency 500
```

### Security-Focused Scanning

```bash
# Only show security issues (hide secure ports)
vow scan server.example.com --issues-only

# Quick security audit of critical services
vow scan database-server --ports 22,1433,3306,5432,6379,27017

# JSON output for automation/CI
vow scan production-server --format json --issues-only > security-report.json
```

### Network Scanning

```bash
# Scan a subnet (limited to /24 for safety)
vow scan 192.168.1.0/24 --ports 22,80,443

# Timeout adjustment for slow networks
vow scan remote-server --timeout 3000 --ports 1-1000
```

## Security Evaluation

### Risk Levels

- **🚨 Critical**: Services that should never be exposed (Redis, MongoDB, databases)
- **⚠️ High**: Insecure protocols or dangerous exposures (Telnet, FTP, databases)
- **ℹ️ Medium**: Services requiring investigation (SSH, HTTP, development ports)
- **💡 Low**: Generally secure services with proper configuration

### Security Status

- **✅ Secure**: Properly secured services (HTTPS, secure mail protocols)
- **❌ Insecure**: Services with known security issues
- **❓ Requires Investigation**: Services that need manual review
- **❓ Unknown**: Unrecognized services

### Common Port Evaluations

| Port | Service | Status | Risk | Recommendation |
|------|---------|--------|------|----------------|
| 22 | SSH | Review | Medium | Use key-based auth, disable passwords |
| 23 | Telnet | Insecure | Critical | Replace with SSH immediately |
| 80 | HTTP | Insecure | Medium | Redirect all traffic to HTTPS |
| 443 | HTTPS | Secure | Low | Ensure valid certificates |
| 1433 | SQL Server | Insecure | Critical | Never expose to internet |
| 3306 | MySQL | Insecure | Critical | Use VPN or firewall rules |
| 3389 | RDP | Insecure | Critical | High attack target, use VPN |
| 6379 | Redis | Insecure | Critical | No built-in encryption |

## Integration Examples

### CI/CD Pipeline

```bash
# Exit with code 1 if critical security issues found
vow scan $PRODUCTION_SERVER --issues-only --format json | jq '.summary.critical_issues' | grep -q '^0$' || exit 1
```

### Monitoring Script

```bash
#!/bin/bash
# Daily security audit
servers=("web1.example.com" "db1.example.com" "api.example.com")

for server in "${servers[@]}"; do
    echo "Scanning $server..."
    vow scan "$server" --issues-only --format json > "reports/${server}-$(date +%Y%m%d).json"
done
```

### Security Dashboard Data

```bash
# Generate data for security dashboard
vow scan production-network.local/24 --ports 22,80,443,1433,3306,3389,5432 --format json > daily-security-scan.json
```

## Configuration Options

### Command Line Options

- `--ports` / `-p`: Port specification (ranges, lists, or combinations)
- `--format` / `-f`: Output format (terminal, json)
- `--timeout`: Connection timeout in milliseconds (default: 1000)
- `--concurrency` / `-c`: Number of concurrent connections (default: 100)
- `--issues-only`: Only show security issues, hide secure ports

### Performance Tuning

- **Low bandwidth**: Increase `--timeout`, reduce `--concurrency`
- **Fast networks**: Increase `--concurrency` for faster scans
- **Large ranges**: Use `--issues-only` to focus on problems
- **Stealth scanning**: Reduce `--concurrency` to avoid detection

## Security Best Practices

1. **Firewall Configuration**: Block unnecessary ports at the firewall level
2. **Service Hardening**: Configure services with security best practices
3. **Regular Audits**: Run port scans regularly to detect new exposures
4. **Monitoring**: Set up alerts for unexpected open ports
5. **Principle of Least Privilege**: Only expose services that are absolutely necessary

## Exit Codes

- `0`: No critical security issues found
- `1`: Critical security issues detected or scanning errors

This makes `vow scan` suitable for use in automated security pipelines and monitoring systems.