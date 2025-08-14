```markdown
# EC2 Security Scanner - Documentation

## Overview

The CloudSecVision EC2 Security Scanner is designed to identify risky security group configurations in your Amazon EC2 environment. This module focuses on detecting overly permissive security group rules that could potentially expose your infrastructure to unauthorized access.

## Core Functionalities

### Security Group Analysis

The EC2 scanner examines all security groups in the AWS account to identify those that:

1. **Allow SSH (port 22) from anywhere**: Security groups permitting SSH access from 0.0.0.0/0 or ::/0
2. **Expose sensitive ports**: Identifies critical ports (e.g., 3389 RDP, 1433 SQL Server) open to the internet
3. **Have overly permissive rules**: Security groups allowing broad access to multiple ports
4. **Misconfigured egress rules**: Security groups with unrestricted outbound traffic

### Risk Assessment

Each identified security group is analyzed for:

- **Exposure level**: How broadly the ports are accessible
- **Service sensitivity**: Which potentially vulnerable services are exposed
- **Instance impact**: Which EC2 instances are affected by the risky configuration

### Report Generation

The scanner produces a JSON-formatted report with:
- Security Group ID and name
- Issue description
- Severity level
- Port information
- CIDR ranges of concern
- Recommended remediation steps

## Integration with AI Analysis

The EC2 Scanner integrates with CloudSecVision's AI analysis system to:

1. Provide contextual explanations of security issues
2. Generate specific remediation recommendations
3. Assess the overall security posture
4. Format findings for better comprehension

## Implementation Details

### Scanning Method

The scanner uses AWS SDK (boto3) to:
1. List all security groups in the account
2. Analyze each security group's ingress and egress rules
3. Flag potentially risky configurations
4. Associate findings with the affected security groups

### Detection Logic

Security groups are flagged for issues when they:
- Allow access from 0.0.0.0/0 or ::/0 to sensitive ports
- Permit broad port ranges (e.g., all ports) from public IP ranges
- Have rules that expose administrative interfaces
- Allow unrestricted outbound access to sensitive destinations

## Usage

### Basic Invocation

```python
from scan.scan_ec2 import scan_ec2_security_groups

# Run the scan
results = scan_ec2_security_groups()
```

### Output Example

```json
[
  {
    "SecurityGroupId": "sg-0123456789abcdef0",
    "SecurityGroupName": "WebServerSG",
    "Issue": "SSH (port 22) exposed to the internet (0.0.0.0/0)",
    "Protocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRange": "0.0.0.0/0",
    "Severity": "HIGH"
  }
]
```

## Best Practices

- Run the EC2 scanner regularly as part of security checks
- Review and remediate all identified issues
- Implement security group rules based on the principle of least privilege
- Use security group references instead of public CIDR ranges when possible
- Implement a bastion host architecture for administrative access

## Limitations

- Focuses on security group configurations, not instance-level vulnerabilities
- Does not scan for vulnerabilities within the EC2 instances themselves
- Cannot detect issues in unused but misconfigured security groups
- Does not evaluate network ACLs or subnet route tables
```
