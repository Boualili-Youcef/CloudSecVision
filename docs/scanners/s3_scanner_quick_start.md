# S3 Security Scanner - Quick Start Guide

This guide will help you quickly get started with the S3 Security Scanner tool.

## Prerequisites

Before using the S3 Security Scanner, ensure you have:

1. Python 3.6 or higher installed
2. AWS credentials configured (via environment variables, credentials file, or IAM role)
3. Required Python packages installed:
   ```
   pip install boto3
   ```

## Running the Scanner

To run a full security scan of your S3 buckets:

1. Navigate to the project root directory
2. Execute:
   ```bash
   python3 scan/scan_s3.py
   ```

## Understanding the Output

The scanner provides real-time feedback during execution:

```
🛡️ CloudSecVision - Advanced S3 Security Scanner
==================================================
🌐 Found 5 S3 buckets to analyze

🔍 Scanning bucket: example-bucket-1
   📁 Found 10+ objects
   ⚠️  1 HIGH issues
   🟡 2 MEDIUM issues
   🔵 1 LOW issues

🔍 Scanning bucket: example-bucket-2
   📁 Found 10+ objects
   ✅ No security issues found

...

==================================================
📊 SCAN SUMMARY:
   🏢 Buckets scanned: 5
   ⚠️  Total issues: 5
   HIGH: 1 issues
   MEDIUM: 3 issues
   LOW: 1 issues

✅ Detailed report saved: /path/to/s3_scan_report.json
```

## Interpreting Results

Issues are categorized by severity:

- 🚨 **CRITICAL** - Immediate action required
- ⚠️ **HIGH** - Address as soon as possible
- 🟡 **MEDIUM** - Plan to fix in near term
- 🔵 **LOW** - Best practice recommendations

## Viewing Detailed Results

The detailed JSON report is saved to `scan/results/s3_scan_report.json`. You can:

1. Open it in any text editor or JSON viewer
2. Import it into security dashboards
3. Process it with other analysis tools

## Common Issues Detected

The scanner checks for several common S3 security issues:

1. **Public Access**
   - Public bucket policies
   - Public ACL grants
   - Missing Block Public Access settings

2. **Data Protection**
   - Missing encryption
   - Disabled versioning
   - Missing MFA Delete

3. **Best Practices**
   - Access logging configuration
   - Lifecycle policies

## Example Remediation Steps

For common findings, here are quick remediation steps:

### Enable Block Public Access
```bash
aws s3api put-public-access-block \
  --bucket YOUR-BUCKET-NAME \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Enable Default Encryption
```bash
aws s3api put-bucket-encryption \
  --bucket YOUR-BUCKET-NAME \
  --server-side-encryption-configuration \
  '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": true}]}'
```

### Enable Versioning
```bash
aws s3api put-bucket-versioning \
  --bucket YOUR-BUCKET-NAME \
  --versioning-configuration Status=Enabled
```

### Enable Access Logging
```bash
aws s3api put-bucket-logging \
  --bucket YOUR-BUCKET-NAME \
  --bucket-logging-status \
  '{"LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "YOUR-BUCKET-NAME/"}}'
```

## Next Steps

After scanning your S3 buckets:

1. Address any CRITICAL or HIGH severity issues immediately
2. Create a remediation plan for MEDIUM and LOW issues
3. Integrate the scanner into your CI/CD or monitoring workflows
4. Consider setting up recurring scans for continuous security assessment
