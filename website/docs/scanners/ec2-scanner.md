---
sidebar_position: 3
---

# EC2 Scanner

The EC2 Scanner examines security group configurations to identify overly permissive network access rules that could expose your infrastructure to unauthorized access.

## Overview

The EC2 Scanner (`scan/scan_ec2.py`) analyzes all security groups in your AWS account to detect potentially risky network configurations. It focuses on identifying security groups that allow broad access to sensitive ports, particularly SSH access from the internet.

## How It Works

### Scanning Process

1. **Security Group Discovery**: Lists all security groups across all VPCs
2. **Rule Analysis**: Examines ingress rules for each security group
3. **Risk Assessment**: Identifies rules that allow broad public access
4. **Report Generation**: Creates a detailed JSON report with findings

### Detection Logic

The scanner currently focuses on **SSH exposure** and flags security groups that:

- Allow SSH (port 22) from `0.0.0.0/0` (all IPv4 addresses)
- Allow SSH (port 22) from `::/0` (all IPv6 addresses)
- Use TCP protocol or "all protocols" (-1) for SSH access

## Key Features

### 🔍 Comprehensive Network Analysis
- Scans **all security groups** in the account
- Analyzes both **IPv4 and IPv6** configurations
- Examines **ingress rules** for public exposure
- Supports both **TCP and all-protocol** rules

### 🚨 Critical Security Detection
- **SSH Exposure**: Identifies SSH ports open to the internet
- **Administrative Access**: Detects remote administration vulnerabilities
- **Protocol Analysis**: Examines specific and wildcard protocols
- **CIDR Range Evaluation**: Identifies overly broad network access

### 📊 Detailed Reporting
- Security group ID and name for easy identification
- Specific port and protocol information
- IP range details (IPv4/IPv6)
- Clear issue descriptions for remediation

## Usage Examples

### Command Line Execution

```bash
# Run EC2 scanner
python -m scan.scan_ec2
```

**Output:**
```
✅ EC2 report generated at scan/results/ec2_scan.json (3 issues found)
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

## Report Format

The scanner generates a JSON report with the following structure:

```json
[
  {
    "GroupId": "sg-0123456789abcdef0",
    "GroupName": "web-servers",
    "Port": 22,
    "IpRange": "0.0.0.0/0",
    "Issue": "SSH port 22 open to the world"
  },
  {
    "GroupId": "sg-0987654321fedcba0", 
    "GroupName": "admin-access",
    "Port": 22,
    "IpRange": "::/0",
    "Issue": "SSH port 22 open to the world (IPv6)"
  }
]
```

### Report Fields

- **GroupId**: Security group identifier (sg-xxxxxxxxx)
- **GroupName**: Human-readable security group name
- **Port**: The exposed port number (currently focuses on 22)
- **IpRange**: The CIDR range allowing access
- **Issue**: Description of the security concern

## Common Findings

### 1. SSH Open to Internet (IPv4)

**Security Group Rule:**
```
Type: SSH
Protocol: TCP
Port: 22
Source: 0.0.0.0/0
```

**Risk**: SSH access from any internet address
**Recommendation**: Restrict to specific IP ranges or use a bastion host

### 2. SSH Open to Internet (IPv6)

**Security Group Rule:**
```
Type: SSH
Protocol: TCP  
Port: 22
Source: ::/0
```

**Risk**: SSH access from any IPv6 address globally
**Recommendation**: Remove IPv6 rule or restrict to specific ranges

### 3. All Protocols SSH Access

**Security Group Rule:**
```
Type: All Traffic
Protocol: All
Port: All
Source: 0.0.0.0/0
```

**Risk**: Complete network access including SSH
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

## Future Enhancements

The EC2 scanner is actively developed. Planned enhancements include:

- **Multi-Port Support**: Detection of other critical ports (RDP, databases)
- **Egress Rule Analysis**: Scanning outbound traffic rules
- **VPC Flow Log Integration**: Correlation with actual traffic patterns
- **Instance Association**: Mapping which instances use risky security groups
- **Severity Scoring**: Risk-based prioritization of findings

## Next Steps

- [S3 Scanner](./s3-scanner) - Learn about storage security scanning
- [Configuration](./configuration) - Customize scanner behavior
- [AI Analysis](../ai-analysis/overview) - Get detailed security recommendations
- [Dashboard](../dashboard/overview) - Visualize your network security posture
