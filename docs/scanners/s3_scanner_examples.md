# S3 Security Scanner - Examples and Use Cases

This document provides practical examples and use cases for the S3 Security Scanner.

## Example 1: Basic Security Audit

The most common use case is a periodic security audit of all S3 buckets:

```bash
# Run from project root
python3 scan/scan_s3.py
```

This scan will:
- Check all S3 buckets in the account
- Generate a consolidated security report
- Save findings to a JSON file for documentation

## Example 2: Integration with Security Workflows

Add the scanner to automated security pipelines:

```bash
#!/bin/bash
# Example security pipeline script

# Run S3 scanner
echo "Running S3 security scan..."
python3 /path/to/scan/scan_s3.py

# Check for critical issues
if grep -q "CRITICAL" scan/results/s3_scan_report.json; then
  echo "CRITICAL S3 security issues found!"
  exit 1
else
  echo "No critical S3 issues found."
fi
```

## Example 3: Custom Security Checking

You can use the S3SecurityScanner class in your own Python scripts:

```python
from scan.scan_s3 import S3SecurityScanner

def check_specific_buckets(bucket_list):
    scanner = S3SecurityScanner()
    results = []
    
    for bucket in bucket_list:
        print(f"Scanning {bucket}...")
        bucket_results = scanner.scan_bucket_comprehensive(bucket)
        results.extend(bucket_results)
    
    return results

# Only scan production buckets
prod_buckets = ["prod-data", "prod-backups", "prod-logs"]
issues = check_specific_buckets(prod_buckets)

# Process results
for issue in issues:
    if issue.get("Severity") in ["CRITICAL", "HIGH"]:
        # Alert security team
        send_alert(issue)
```

## Example 4: Parsing and Analyzing Results

Example of how to process the JSON results:

```python
import json

# Load scan results
with open('scan/results/s3_scan_report.json', 'r') as f:
    scan_results = json.load(f)

# Group issues by bucket
bucket_issues = {}
for issue in scan_results:
    bucket_name = issue.get('BucketName')
    if bucket_name not in bucket_issues:
        bucket_issues[bucket_name] = []
    bucket_issues[bucket_name].append(issue)

# Find buckets with critical issues
critical_buckets = []
for bucket, issues in bucket_issues.items():
    if any(issue.get('Severity') == 'CRITICAL' for issue in issues):
        critical_buckets.append(bucket)

print(f"Buckets with CRITICAL issues: {critical_buckets}")
```

## Use Case: Post-Deployment Verification

Use the scanner to verify that newly deployed S3 buckets comply with security policies:

1. Create a new S3 bucket through Infrastructure as Code
2. Run the S3 scanner immediately after deployment
3. Verify no security issues exist
4. If issues are found, either fix automatically or fail the deployment

## Use Case: Continuous Compliance Monitoring

Set up the scanner to run on a schedule:

1. Configure a daily cron job to execute the scanner
2. Send results to a security monitoring system
3. Track compliance metrics over time
4. Generate alerts for any new issues

## Use Case: Security Incident Response

During security incidents:

1. Run the scanner to get a current snapshot of S3 security
2. Identify any buckets that may have been compromised
3. Use findings to guide remediation efforts
4. Run scan again after remediation to verify issues are fixed

## Use Case: Security Assessment Reports

Generate security assessment documentation:

1. Run the S3 scanner as part of a broader security assessment
2. Include the findings in security reports for management or auditors
3. Use the severity classifications to prioritize remediation efforts
4. Track improvements in security posture over time

## Use Case: Pre-audit Preparation

Before compliance audits:

1. Run the scanner to identify any non-compliant S3 configurations
2. Address issues before external auditors find them
3. Generate evidence of security controls for auditors
4. Demonstrate proactive security monitoring
