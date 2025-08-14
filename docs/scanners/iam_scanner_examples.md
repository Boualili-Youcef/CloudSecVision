```markdown
# IAM Security Scanner - Examples and Use Cases

This document provides practical examples and common use cases for the IAM Security Scanner in CloudSecVision.

## Basic Usage Examples

### 1. Standalone Command Line Scan

Run a quick IAM security scan from the command line:

```bash
# Navigate to the project directory
cd cloudsecvision

# Run the IAM scanner module
python3 -m scan.scan_iam
```

Output:
```
✅ IAM report generated at scan/results/iam_scan_report.json (2 issues found)
```

### 2. Integration with Main Script

Run the IAM scanner as part of a comprehensive security assessment:

```bash
# Run only IAM scanner
python3 main.py --service iam

# Run IAM scanner with AI analysis
python3 main.py --service iam --ai
```

### 3. Dashboard Integration

```python
# From dashboard.py
from scan.scan_iam import scan_iam_permissions
from analysis.ai_analyzer import generate_iam_report

# Run scan
iam_results = scan_iam_permissions()

# Generate AI report
iam_analysis = generate_iam_report(iam_results)
```

## Common Use Cases

### 1. Security Compliance Check

**Scenario**: Verify IAM policies comply with security best practices before an audit.

**Implementation**:
```python
# Run scan and check results
iam_issues = scan_iam_permissions()

# Check for non-compliance
non_compliant = len(iam_issues) > 0

if non_compliant:
    print("⚠️ Found non-compliant IAM policies:")
    for issue in iam_issues:
        print(f"  - {issue['PolicyName']}: {issue['Issue']}")
else:
    print("✅ All IAM policies are compliant")
```

### 2. DevOps Pipeline Integration

**Scenario**: Automated security scanning as part of CI/CD pipeline.

```bash
#!/bin/bash
# CI/CD Script

# Clone repository
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision

# Setup environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run IAM security scan
python3 -m scan.scan_iam

# Check for critical issues
if grep -q "Too permissive" scan/results/iam_scan_report.json; then
  echo "PIPELINE FAILED: Critical IAM security issues detected"
  exit 1
else
  echo "IAM security check passed"
fi
```

### 3. Regular Security Auditing

**Scenario**: Weekly security audit of IAM policies.

**Implementation using cron job**:
```bash
# /etc/cron.weekly/iam-security-scan
#!/bin/bash

cd /path/to/cloudsecvision
source venv/bin/activate

# Run scan
python3 main.py --service iam --ai

# Send report by email
if [ -f scan/results/iam_scan_report.json ]; then
  mail -s "Weekly IAM Security Report" security@example.com < scan/results/iam_scan_report.json
fi
```

## Advanced Examples

### 1. Custom Policy Evaluation

Extend the scanner with custom policy evaluation logic:

```python
def check_for_dangerous_permissions(policy_doc):
    """Check for specifically dangerous permission combinations"""
    dangerous_combinations = [
        {"service": "iam", "actions": ["CreatePolicy", "AttachRolePolicy"]},
        {"service": "lambda", "actions": ["CreateFunction", "InvokeFunction"]}
    ]
    
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
            
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
            
        # Check for dangerous combinations
        for combo in dangerous_combinations:
            service = combo["service"]
            matches = [a for a in actions if a.startswith(f"{service}:") or a == "*"]
            if len(matches) >= len(combo["actions"]):
                return True
                
    return False
```

### 2. Integrating with Security Information and Event Management (SIEM)

```python
import json
import requests
from scan.scan_iam import scan_iam_permissions

# Run IAM security scan
iam_issues = scan_iam_permissions()

# Format for SIEM ingestion
siem_events = []
for issue in iam_issues:
    siem_events.append({
        "timestamp": datetime.now().isoformat(),
        "event_type": "security_finding",
        "severity": "HIGH" if "*" in issue.get("Issue", "") else "MEDIUM",
        "source": "cloudsecvision",
        "description": f"IAM Policy Issue: {issue['Issue']}",
        "resource": issue["Arn"],
        "resource_type": "iam_policy"
    })

# Send to SIEM API
response = requests.post(
    "https://siem.example.com/api/events",
    headers={"Authorization": "Bearer TOKEN", "Content-Type": "application/json"},
    data=json.dumps(siem_events)
)
```

## Troubleshooting Examples

### 1. Handling Missing Permissions

```python
import boto3
from botocore.exceptions import ClientError

def scan_with_error_handling():
    try:
        return scan_iam_permissions()
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            print("❌ Error: Insufficient permissions to scan IAM policies")
            print("Required permissions: iam:ListPolicies, iam:GetPolicy, iam:GetPolicyVersion")
            return []
        else:
            raise
```

### 2. Scanning Large Accounts

For AWS accounts with many policies, avoid throttling:

```python
import time
import boto3

def scan_large_account():
    iam = boto3.client('iam')
    results = []
    
    # Use pagination to handle many policies
    paginator = iam.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local', OnlyAttached=True):
        for policy in page['Policies']:
            # Process policy
            policy_name = policy['PolicyName']
            policy_arn = policy['Arn']
            
            # Add delay to avoid throttling
            time.sleep(0.5)
            
            # Continue processing...
            
    return results
```
```
