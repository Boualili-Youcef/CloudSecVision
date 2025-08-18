---
sidebar_position: 3
---

# EC2 Scanner

The EC2 Scanner provides **enterprise-grade security analysis** of your AWS EC2 infrastructure, identifying vulnerabilities across security groups, instances, load balancers, and VPC configurations with professional-grade reporting and compliance mapping.

## Overview

The EC2 Scanner (`scan/scan_ec2.py`) is a comprehensive security assessment tool that performs **25+ vulnerability checks** across your AWS EC2 environment. It goes far beyond basic port scanning to provide enterprise-level security analysis with structured findings, severity scoring, and compliance impact assessment.

## How It Works

### Comprehensive Scanning Process

1. **Security Group Analysis**: Deep inspection of all security groups with advanced rule analysis
2. **EC2 Instance Security**: Comprehensive instance-level security assessment
3. **Load Balancer Security**: Analysis of ALB/CLB configurations and SSL/TLS settings
4. **VPC Flow Log Compliance**: Network monitoring and logging verification
5. **Security Scoring**: Risk-based scoring algorithm (0-100) with compliance mapping
6. **Professional Reporting**: Structured JSON reports with actionable remediation steps

### Advanced Detection Logic

The scanner performs **25+ security checks** including:

#### **Network Security (Critical)**
- **SSH/RDP Exposure**: Detects administrative ports open to internet
- **Database Ports**: MySQL, PostgreSQL, Redis, MongoDB exposure
- **All Traffic Rules**: Critical detection of unrestricted access
- **Wide Port Ranges**: Identifies overly broad network access
- **Protocol Analysis**: TCP/UDP/All protocol security assessment

#### **Instance Security**
- **Public IP Analysis**: Instances with direct internet exposure
- **EBS Encryption**: Unencrypted storage volumes detection
- **IMDSv1 Vulnerabilities**: Instance metadata service security flaws
- **AMI Age Assessment**: Outdated AMI usage detection
- **Monitoring Compliance**: CloudWatch detailed monitoring status

## Key Features

### 🔍 **Enterprise-Grade Security Analysis**
- **25+ Vulnerability Checks** across EC2 infrastructure
- **Multi-Layer Assessment**: Security groups, instances, load balancers, VPC
- **Critical Port Detection**: SSH, RDP, databases, and administrative services
- **Compliance Mapping**: CIS AWS Foundations, GDPR, HIPAA, PCI-DSS alignment
- **Advanced Rule Logic**: Multiple vulnerability detection per security rule

### 🚨 **Professional Vulnerability Detection**
- **CRITICAL Ports**: SSH (22), RDP (3389), Telnet (23) internet exposure
- **Database Security**: MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch
- **Infrastructure Flaws**: Public instances, unencrypted EBS, IMDSv1 vulnerabilities
- **Load Balancer Security**: HTTP exposure, SSL/TLS configuration issues
- **Network Monitoring**: VPC Flow Log compliance verification

### 📊 **Structured Professional Reporting**
- **Security Score**: Risk-based algorithm (0-100) with clear risk levels
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW with compliance impact
- **Actionable Recommendations**: Step-by-step remediation guidance
- **Resource Tracking**: Detailed resource IDs and types for precise fixing
- **Compliance Impact**: Regulatory and framework violation mapping

### ⚡ **Advanced Technical Features**
- **Independent Vulnerability Checks**: Multiple findings per security rule
- **Resource Correlation**: Cross-service security analysis
- **Performance Optimized**: Batch processing for large-scale environments
- **Error Resilience**: Graceful handling of permission and API limitations

## Usage Examples

### Command Line Execution

```bash
# Run comprehensive EC2 security scan
python -m scan.scan_ec2
```

**Enterprise-Grade Output:**
```
🚀 Starting Comprehensive EC2 Security Scan...
==================================================
🔍 Scanning Security Groups for vulnerabilities...
🔍 Scanning EC2 Instances for vulnerabilities...
🔍 Scanning Load Balancers for vulnerabilities...
🔍 Checking VPC Flow Logs...

==================================================
📊 EC2 SECURITY SCAN SUMMARY
==================================================
🔍 Total Issues Found: 12
🚨 Critical: 3
⚠️  High: 5
📋 Medium: 3
ℹ️  Low: 1
📊 Security Score: 42/100
🎯 Risk Level: HIGH
✅ Report saved to: scan/results/ec2_scan.json
==================================================
```

### Integration with Main Script

```bash
# Run only EC2 scanner
python main.py --service ec2

# Run EC2 scanner with AI analysis
python main.py --service ec2 --ai
```

### Dashboard Usage

```bash
# Launch dashboard and navigate to EC2 tab
./run_dashboard.sh
```

## Professional Report Format

The scanner generates a comprehensive JSON report with enterprise-grade structure:

```json
{
  "scan_timestamp": "2025-08-18T10:30:45.123456",
  "total_issues": 12,
  "critical_issues": 3,
  "high_issues": 5,
  "medium_issues": 3,
  "low_issues": 1,
  "security_score": 42,
  "risk_level": "HIGH",
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Network Security",
      "title": "SSH Port Open to Internet",
      "description": "Security group web-servers (sg-0123456789abcdef0) has SSH port 22 open to the entire internet (0.0.0.0/0)",
      "resource_id": "sg-0123456789abcdef0",
      "resource_type": "SecurityGroup",
      "recommendation": "Restrict SSH access to specific IP ranges or use VPN/bastion host",
      "compliance_impact": "Violates CIS AWS Foundations Benchmark 4.1-4.2",
      "timestamp": "2025-08-18T10:30:45.234567"
    },
    {
      "severity": "HIGH",
      "category": "Data Protection",
      "title": "Unencrypted EBS Volume",
      "description": "EBS volume vol-0987654321fedcba0 attached to instance i-0123456789abcdef0 is not encrypted",
      "resource_id": "vol-0987654321fedcba0",
      "resource_type": "EBSVolume",
      "recommendation": "Enable EBS encryption for all volumes to protect data at rest",
      "compliance_impact": "Violates data protection regulations (GDPR, HIPAA, PCI-DSS)",
      "timestamp": "2025-08-18T10:30:45.345678"
    }
  ]
}
```

### Enhanced Report Structure

#### **Executive Summary**
- **scan_timestamp**: ISO timestamp of scan execution
- **security_score**: Risk-based score (0-100, higher = more secure)
- **risk_level**: Overall assessment (LOW/MEDIUM/HIGH/CRITICAL)
- **Issue counts**: Breakdown by severity level

#### **Detailed Findings**
- **severity**: CRITICAL/HIGH/MEDIUM/LOW classification
- **category**: Security domain (Network Security, Data Protection, etc.)
- **title**: Concise vulnerability description
- **description**: Detailed technical explanation
- **resource_id**: Specific AWS resource identifier
- **resource_type**: AWS resource type for precise targeting
- **recommendation**: Actionable remediation steps
- **compliance_impact**: Regulatory and framework implications
- **timestamp**: Individual finding discovery time

## Comprehensive Vulnerability Coverage

### 🚨 **CRITICAL Findings**

#### 1. All Traffic Open to Internet
**Security Group Rule:**
```
Type: All Traffic
Protocol: All (-1)
Port: All (0-65535)
Source: 0.0.0.0/0
```
**Risk Level**: CRITICAL
**Impact**: Complete infrastructure exposure
**Compliance**: Major security violation - immediate remediation required

#### 2. SSH Port Open to Internet
**Security Group Rule:**
```
Type: SSH
Protocol: TCP
Port: 22
Source: 0.0.0.0/0
```
**Risk Level**: CRITICAL
**Impact**: Administrative access from anywhere
**Compliance**: Violates CIS AWS Foundations Benchmark 4.1-4.2

#### 3. RDP Port Open to Internet
**Security Group Rule:**
```
Type: RDP
Protocol: TCP
Port: 3389
Source: 0.0.0.0/0
```
**Risk Level**: CRITICAL
**Impact**: Windows remote desktop access exposure

### ⚠️ **HIGH Severity Findings**

#### 4. Database Ports Exposed
**MySQL Example:**
```
Type: MySQL/Aurora
Protocol: TCP
Port: 3306
Source: 0.0.0.0/0
```
**Detected Databases**: MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), Elasticsearch (9200)

#### 5. Public EC2 Instances
**Risk**: Direct internet exposure bypassing load balancers
**Detection**: Instances with public IP addresses
**Impact**: Increases attack surface significantly

#### 6. Unencrypted EBS Volumes
**Risk**: Data at rest not protected
**Detection**: EBS volumes without encryption
**Compliance**: Violates GDPR, HIPAA, PCI-DSS requirements

#### 7. Wide Port Ranges Open
**Example:**
```
Type: Custom TCP
Protocol: TCP
Port Range: 8000-9000
Source: 0.0.0.0/0
```
**Risk**: Excessive network exposure

### 📋 **MEDIUM Severity Findings**

#### 8. IMDSv1 Enabled
**Risk**: Vulnerable to SSRF attacks
**Detection**: Instance metadata service v1 allowed
**Impact**: Potential credential theft

#### 9. Load Balancer HTTP Usage
**Risk**: Data transmitted in plaintext
**Detection**: ALB/CLB with HTTP listeners
**Compliance**: Violates security standards

#### 10. VPC Flow Logs Disabled
**Risk**: Reduced network monitoring capability
**Detection**: VPCs without flow logs
**Impact**: Limited security incident response

### ℹ️ **LOW Severity Findings**

#### 11. Unused Security Groups
**Risk**: Management overhead and potential misconfigurations
**Detection**: Security groups not attached to resources

#### 12. Detailed Monitoring Disabled
**Risk**: Reduced visibility into system performance
**Detection**: EC2 instances without CloudWatch detailed monitoring
**Recommendation**: Use specific protocols and ports only

## Security Implications

### Attack Vectors

1. **Brute Force Attacks**: Open SSH ports are targets for credential attacks
2. **Automated Scanning**: Internet-wide scanning tools identify open SSH ports
3. **Lateral Movement**: Compromised instances can be used to access other resources
4. **Data Exfiltration**: SSH access can be used to transfer sensitive data

### Compliance Impact

- **PCI DSS**: Requires restricted access to cardholder data environments
- **SOC 2**: Mandates logical access controls and network restrictions
- **ISO 27001**: Requires network access control policies
- **CIS Benchmarks**: Recommends restricting SSH access to specific networks

## Remediation Strategies

### 1. IP Address Whitelisting

Replace broad access with specific IP ranges:

**Before:**
```
Source: 0.0.0.0/0 (everywhere)
```

**After:**
```
Source: 203.0.113.0/24 (your office network)
Source: 198.51.100.50/32 (specific admin IP)
```

### 2. Bastion Host Architecture

Implement a secure bastion host pattern:

```
Internet → Bastion Host (restricted IPs) → Private Instances
         (SSH from office only)    (SSH from bastion only)
```

**Benefits:**
- Single point of SSH access control
- Centralized logging and monitoring
- Reduced attack surface

### 3. VPN-Based Access

Use VPN for administrative access:

```
Admin → VPN Gateway → Private Network → EC2 Instances
       (authenticated)  (internal IPs)   (no public SSH)
```

### 4. AWS Systems Manager (SSM)

Replace SSH with Systems Manager Session Manager:

**Advantages:**
- No inbound ports required
- IAM-based access control
- Full session logging
- Browser-based access

```bash
# Connect via SSM instead of SSH
aws ssm start-session --target i-1234567890abcdef0
```

## Advanced Configuration

### Custom Port Detection

While the current scanner focuses on SSH (port 22), you can extend it to detect other critical ports:

```python
# Additional ports to check
CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP (Windows Remote Desktop)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database", 
    6379: "Redis",
    27017: "MongoDB"
}
```

### Protocol-Specific Analysis

```python
# Check for different protocol exposures
def analyze_protocol_exposure(permission):
    protocol = permission.get('IpProtocol')
    
    if protocol == '-1':  # All protocols
        return "All protocols exposed"
    elif protocol == 'tcp':
        return analyze_tcp_ports(permission)
    elif protocol == 'udp':
        return analyze_udp_ports(permission)
```

## Integration with AI Analysis

When run with AI analysis (`--ai` flag), the EC2 scanner provides:

### Enhanced Analysis
- **Risk Assessment**: Detailed explanation of network security risks
- **Context Awareness**: Understanding of your infrastructure patterns
- **Prioritized Remediation**: Step-by-step fixes ordered by importance
- **Compliance Mapping**: How findings relate to security frameworks

### Example AI Report

```markdown
## EC2 Security Group Analysis

### Executive Summary
Your network configuration shows 3 security groups with SSH access 
exposed to the internet, creating significant security risks...

### Risk Level: HIGH

### Detailed Analysis
The identified security groups allow SSH access from any internet address,
making your instances vulnerable to brute force attacks and unauthorized access...

### Priority Actions
1. Immediately restrict SSH access to known IP ranges
2. Implement bastion host architecture for secure access
3. Enable VPC Flow Logs for network monitoring
4. Consider AWS Systems Manager for serverless remote access
```

## Best Practices

### Before Scanning
1. **Verify Permissions**: Ensure scanner has `ec2:DescribeSecurityGroups` permission
2. **Multi-Region**: Consider scanning all AWS regions where you have resources
3. **VPC Coverage**: Ensure all VPCs are included in the scan

### Interpreting Results
1. **Context Matters**: Consider the purpose of each security group
2. **Environment Classification**: Production systems require stricter controls
3. **Access Patterns**: Legitimate admin access may show as findings

### Taking Action
1. **Test Changes**: Verify access works after restricting security groups
2. **Communication**: Notify teams before changing network access
3. **Backup Access**: Ensure alternative access methods before removing SSH
4. **Monitor Changes**: Watch for connection issues after modifications

## Performance Considerations

### API Limits
- EC2 `DescribeSecurityGroups` has a rate limit of 100 requests per second
- Large accounts with many security groups may require throttling
- Consider paginated requests for accounts with 1000+ security groups

### Optimization Tips
```python
# Batch process security groups
def scan_in_batches(security_groups, batch_size=50):
    for i in range(0, len(security_groups), batch_size):
        batch = security_groups[i:i + batch_size]
        process_batch(batch)
        time.sleep(0.1)  # Rate limiting
```

## Troubleshooting

### Common Issues

**No Security Groups Found**
```
✅ EC2 report generated at scan/results/ec2_scan.json (0 issues found)
```
- **Cause**: No security groups with SSH open to internet
- **Action**: This is good - your network is properly secured

**Permission Denied**
```
ClientError: User is not authorized to perform: ec2:DescribeSecurityGroups
```
- **Cause**: Insufficient EC2 permissions
- **Solution**: Add `ec2:DescribeSecurityGroups` permission

**Empty Security Groups**
```
No security groups returned from API
```
- **Cause**: No EC2 resources in the current region
- **Solution**: Check other AWS regions or verify resource existence

### Debugging Tips

```bash
# Check security groups manually
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?FromPort==`22` && IpRanges[?CidrIp==`0.0.0.0/0`]]]'

# List all security groups
aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId'
```

## Extended Monitoring

### Continuous Monitoring

```bash
#!/bin/bash
# monitor-sg.sh - Check for new SSH exposure

# Run scan
python -m scan.scan_ec2

# Check for new issues
CURRENT_ISSUES=$(cat scan/results/ec2_scan.json | jq length)
PREVIOUS_ISSUES=$(cat scan/results/ec2_scan_previous.json | jq length 2>/dev/null || echo 0)

if [ "$CURRENT_ISSUES" -gt "$PREVIOUS_ISSUES" ]; then
    echo "🚨 New SSH exposure detected!"
    # Send alert
fi

# Save current state
cp scan/results/ec2_scan.json scan/results/ec2_scan_previous.json
```

### Integration with AWS Config

```json
{
  "ConfigRuleName": "ssh-restricted-check",
  "Description": "Checks whether security groups allow unrestricted SSH access",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "INCOMING_SSH_DISABLED"
  },
  "Scope": {
    "ComplianceResourceTypes": [
      "AWS::EC2::SecurityGroup"
    ]
  }
}
```

## Advanced Technical Features

### **Multi-Vulnerability Detection Logic**
The scanner uses **independent security checks** rather than exclusive if/elif logic, ensuring comprehensive vulnerability detection:

```python
# Advanced rule analysis - detects ALL applicable issues
def _analyze_rule(self, sg_id, sg_name, from_port, to_port, protocol, cidr, ip_version):
    """Analyze individual security group rule - checks ALL applicable vulnerabilities"""
    
    # Check 1: All traffic open (CRITICAL)
    if protocol == '-1' or (from_port == 0 and to_port == 65535):
        self.add_finding(severity='CRITICAL', title='All Traffic Open to Internet')
    
    # Check 2: Critical ports (independent check)
    if from_port == to_port and from_port in self.CRITICAL_PORTS:
        self.add_finding(severity='CRITICAL', title=f'{port_name} Port Open to Internet')
    
    # Check 3: Wide port ranges (if not already all traffic)
    if (to_port - from_port > 100) and not all_traffic_detected:
        self.add_finding(severity='HIGH', title='Wide Port Range Open to Internet')
```

### **Security Scoring Algorithm**
Enterprise-grade risk scoring with weighted vulnerability assessment:

```python
def generate_security_score(self):
    """Risk-based security scoring (0-100)"""
    # Weighted scoring: Critical=10, High=5, Medium=2, Low=1
    weighted_issues = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
    score = max(0, 100 - min(100, weighted_issues * 2))
    
    # Risk level classification
    if score < 30: risk_level = 'CRITICAL'
    elif score < 50: risk_level = 'HIGH'
    elif score < 70: risk_level = 'MEDIUM'
    else: risk_level = 'LOW'
```

### **Compliance Mapping Engine**
Automatic mapping of findings to security frameworks:
- **CIS AWS Foundations Benchmark**: 4.1-4.2 (Network Access)
- **GDPR**: Data protection and encryption requirements
- **HIPAA**: Healthcare data security mandates
- **PCI-DSS**: Payment card industry standards
- **SOC 2**: System and organization controls

## Recent Enhancements (v2.0)

### ✅ **Implemented Features**
- **25+ Vulnerability Checks**: Comprehensive security assessment
- **Professional Reporting**: Structured JSON with compliance mapping
- **Security Scoring**: Risk-based 0-100 scoring algorithm
- **Multi-Layer Analysis**: Security groups, instances, load balancers, VPC
- **Independent Detection**: Multiple findings per security rule
- **Enterprise Categories**: Network Security, Data Protection, Configuration Management
- **Resource Correlation**: Cross-service security analysis
- **Performance Optimization**: Batch processing and error resilience

### 🔄 **Continuous Improvements**
- Real-time compliance monitoring integration
- Custom vulnerability rule engine
- Multi-region scanning optimization
- Advanced threat modeling integration

## Next Steps

- [S3 Scanner](./s3-scanner) - Learn about storage security scanning
- [Configuration](./configuration) - Customize scanner behavior
- [AI Analysis](../ai-analysis/overview) - Get detailed security recommendations
- [Dashboard](../dashboard/overview) - Visualize your network security posture
