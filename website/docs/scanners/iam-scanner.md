---
sidebar_position: 2
---

# IAM Scanner

The IAM Scanner is designed to identify overly permissive Identity and Access Management policies that could pose security risks to your AWS environment.

## Overview

The IAM Scanner (`scan/scan_iam.py`) analyzes all attached IAM policies in your AWS account to detect potentially dangerous permission configurations. It focuses on identifying policies that use wildcard permissions, which could lead to privilege escalation or unauthorized access.

## How It Works

### Scanning Process

1. **Policy Discovery**: Lists all policies attached to IAM entities (users, roles, groups)
2. **Policy Analysis**: Retrieves the default version of each policy document
3. **Permission Evaluation**: Analyzes policy statements for risky patterns
4. **Report Generation**: Creates a detailed JSON report with findings

### Detection Logic

The scanner flags policies as "too permissive" if they contain:

```json
{
  "Effect": "Allow",
  "Action": "*",      // Wildcard in actions
  "Resource": "*"     // Wildcard in resources
}
```

Or any combination where either `Action` or `Resource` contains wildcards (`*`).

## Key Features

### 🎯 Focused Analysis
- Only scans **attached policies** to reduce noise and API calls
- Ignores unused policies to focus on active security risks
- Analyzes both AWS managed and customer managed policies

### 🚨 Risk Detection
- **Wildcard Actions**: Detects `"Action": "*"` patterns
- **Wildcard Resources**: Identifies `"Resource": "*"` configurations  
- **Combined Risks**: Flags policies with both action and resource wildcards
- **Effect Analysis**: Only flags policies with `"Effect": "Allow"`

### 📊 Comprehensive Reporting
- Policy name and ARN for easy identification
- Clear issue descriptions for quick understanding
- JSON format for programmatic processing
- Integration with AI analysis for detailed recommendations

## Usage Examples

### Command Line Execution

```bash
# Run IAM scanner
python -m scan.scan_iam
```

**Output:**
```
✅ IAM report generated at scan/results/iam_scan_report.json (2 issues found)
```

### Integration with Main Script

```bash
# Run only IAM scanner
python main.py --service iam

# Run IAM scanner with AI analysis
python main.py --service iam --ai
```

### Dashboard Usage

```bash
# Launch dashboard and navigate to IAM tab
./run_dashboard.sh
```

## Report Format

The scanner generates a JSON report with the following structure:

```json
[
  {
    "PolicyName": "TestTooPermissivePolicy",
    "Arn": "arn:aws:iam::123456789012:policy/TestTooPermissivePolicy",
    "Issue": "Too permissive (\"*\" in Action or Resource)"
  },
  {
    "PolicyName": "AdminAccess",
    "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
    "Issue": "Too permissive (\"*\" in Action or Resource)"
  }
]
```

### Report Fields

- **PolicyName**: Human-readable name of the policy
- **Arn**: Amazon Resource Name for unique identification
- **Issue**: Description of the security concern

## Common Findings

### 1. Administrative Policies

**Issue**: Policies granting full administrative access
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**Risk**: Complete AWS account access
**Recommendation**: Use role-based access with specific permissions

### 2. Service-Wide Permissions

**Issue**: Broad service permissions without resource constraints
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
```

**Risk**: Uncontrolled access to all S3 resources
**Recommendation**: Limit to specific buckets and actions

### 3. Resource Wildcards

**Issue**: Specific actions on all resources
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:TerminateInstances",
      "Resource": "*"
    }
  ]
}
```

**Risk**: Ability to terminate any EC2 instance
**Recommendation**: Restrict to specific instances or use conditions

## Remediation Strategies

### 1. Principle of Least Privilege

Replace wildcard permissions with specific, minimal permissions:

**Before:**
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

**After:**
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-specific-bucket/*"
}
```

### 2. Use Conditions

Add conditions to limit when permissions apply:

```json
{
  "Effect": "Allow",
  "Action": "ec2:*",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "ec2:Region": "us-east-1"
    },
    "DateBetween": {
      "aws:CurrentTime": {
        "aws:RequestedRegion": "us-east-1"
      }
    }
  }
}
```

### 3. Role Separation

Separate permissions into different roles:

- **DeveloperRole**: Read-only access to development resources
- **AdminRole**: Administrative access with MFA requirement
- **ServiceRole**: Specific permissions for applications

## Integration with AI Analysis

When run with AI analysis (`--ai` flag), the IAM scanner provides:

### Enhanced Analysis
- Detailed explanation of each finding
- Risk assessment and severity levels
- Specific remediation steps
- Compliance impact analysis

### Example AI Report

```markdown
## IAM Security Analysis

### Executive Summary
Your IAM configuration shows 2 high-risk policies with overly permissive access patterns...

### Risk Level: HIGH

### Detailed Analysis  
The identified policies grant excessive permissions that violate the principle of least privilege...

### Recommendations
1. Replace AdministratorAccess with role-specific permissions
2. Implement policy conditions for time-based access
3. Enable MFA for administrative operations
```

## Best Practices

### Before Scanning
1. **Verify Permissions**: Ensure scanner has `iam:ListPolicies`, `iam:GetPolicy`, and `iam:GetPolicyVersion` permissions
2. **Large Accounts**: Be aware that accounts with many policies may take longer to scan
3. **Rate Limiting**: AWS IAM APIs have rate limits that may slow large scans

### Interpreting Results
1. **False Positives**: Some AWS managed policies (like AdministratorAccess) are intentionally broad
2. **Context Matters**: Consider the purpose and attachment of each policy
3. **Prioritization**: Focus on customer-managed policies first

### Taking Action
1. **Test Changes**: Always test policy changes in a development environment
2. **Document Changes**: Keep records of policy modifications
3. **Monitor Impact**: Watch for application failures after permission changes
4. **Regular Reviews**: Schedule periodic IAM policy audits

## Troubleshooting

### Common Issues

**No Policies Found**
```
✅ IAM report generated at scan/results/iam_scan_report.json (0 issues found)
```
- **Cause**: No attached policies with wildcard permissions
- **Action**: This is actually good - no overly permissive policies detected

**Permission Denied**
```
ClientError: User is not authorized to perform: iam:ListPolicies
```
- **Cause**: Insufficient IAM permissions for the scanner
- **Solution**: Add required IAM permissions to your user/role

**Rate Limiting**
```
Throttling: Request rate exceeded
```
- **Cause**: Too many API calls in a short period
- **Solution**: Wait and retry, or implement exponential backoff

## Performance Optimization

### Efficient Scanning
- Scanner only retrieves attached policies (not all policies)
- Processes policies in batches to respect rate limits
- Caches policy documents to avoid duplicate retrievals

### Large Environment Tips
- Run during off-peak hours to avoid rate limiting
- Consider using IAM roles in multiple regions separately
- Monitor CloudTrail for API usage patterns

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/iam-security.yml
name: IAM Security Scan
on: [push, pull_request]

jobs:
  iam-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run IAM scan
        run: python -m scan.scan_iam
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: iam-scan-results
          path: scan/results/iam_scan_report.json
```

### Automated Alerting

```bash
#!/bin/bash
# iam-alert.sh

# Run IAM scan
python -m scan.scan_iam

# Check for issues
ISSUES=$(cat scan/results/iam_scan_report.json | jq length)

if [ "$ISSUES" -gt 0 ]; then
    echo "⚠️ Found $ISSUES IAM security issues"
    # Send alert (Slack, email, etc.)
    curl -X POST -H 'Content-Type: application/json' \
         -d "{\"text\":\"IAM Security Alert: $ISSUES issues found\"}" \
         "$SLACK_WEBHOOK_URL"
fi
```

## Next Steps

- [EC2 Scanner](./ec2-scanner) - Learn about network security scanning
- [S3 Scanner](./s3-scanner) - Explore storage security assessment  
- [AI Analysis](../ai-analysis/overview) - Understand AI-powered recommendations
- [Dashboard Usage](../dashboard/overview) - Visualize your results
