# S3 Security Scanner Documentation

## Overview

The S3 Security Scanner (`scan_s3.py`) is a comprehensive security assessment tool designed to identify vulnerabilities and misconfigurations in Amazon S3 buckets. This scanner helps organizations ensure their cloud storage follows best security practices by detecting common security issues such as public access, missing encryption, and inadequate logging.

## Features

The scanner performs multiple security checks on each S3 bucket, including:

- **Public Access Checks**: Detects buckets with potentially risky public access configurations
- **Encryption Verification**: Ensures proper server-side encryption is enabled
- **Versioning Assessment**: Verifies if versioning and MFA Delete are properly configured
- **Access Logging**: Checks if access logging is enabled for audit trails
- **Lifecycle Policies**: Identifies buckets without lifecycle management configurations

## Architecture

The S3 Security Scanner uses a modular approach with the main class `S3SecurityScanner` that handles all scanning operations. The scanner:

1. Connects to AWS using boto3
2. Lists all S3 buckets in the account
3. Performs comprehensive security checks on each bucket
4. Aggregates findings and generates a detailed report
5. Saves results as JSON for further analysis

## Class: S3SecurityScanner

### Methods

#### `__init__()`
Initializes the scanner by creating a boto3 S3 client and preparing the results container.

#### `list_buckets()`
Lists all S3 buckets in the AWS account.
- **Returns**: List of bucket names

#### `check_bucket_public_access(bucket_name)`
Performs comprehensive public access checks on a bucket.
- **Parameters**: `bucket_name` (str) - Name of the bucket to check
- **Returns**: List of issues found with severity ratings

Checks performed:
- Block Public Access settings
- Public ACL configurations
- Bucket policy public access grants

#### `check_bucket_encryption(bucket_name)`
Verifies if proper encryption is configured for the bucket.
- **Parameters**: `bucket_name` (str) - Name of the bucket to check
- **Returns**: List of encryption-related issues

Checks performed:
- Presence of server-side encryption configuration
- Strength of encryption algorithm used

#### `check_bucket_versioning(bucket_name)`
Examines bucket versioning configuration.
- **Parameters**: `bucket_name` (str) - Name of the bucket to check
- **Returns**: List of versioning-related issues

Checks performed:
- Versioning status (Enabled/Disabled)
- MFA Delete configuration

#### `check_bucket_logging(bucket_name)`
Verifies if access logging is properly configured.
- **Parameters**: `bucket_name` (str) - Name of the bucket to check
- **Returns**: List of logging-related issues

#### `check_bucket_lifecycle(bucket_name)`
Checks if lifecycle policies are configured.
- **Parameters**: `bucket_name` (str) - Name of the bucket to check
- **Returns**: List of lifecycle-related issues

#### `scan_bucket_comprehensive(bucket_name)`
Performs a complete scan of a bucket using all available check methods.
- **Parameters**: `bucket_name` (str) - Name of the bucket to scan
- **Returns**: Comprehensive list of all issues found

This method:
1. Runs all individual check methods on the bucket
2. Collects statistics about the bucket (object count sample)
3. Categorizes findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
4. Outputs a summary of findings to the console

## Main Function

The `main()` function serves as the entry point for the scanner:

1. Initializes the S3SecurityScanner
2. Lists all buckets in the account
3. Scans each bucket comprehensively
4. Generates a global summary of findings
5. Saves results to a JSON file in the `scan/results` directory

## Severity Levels

Findings are categorized by severity:

- **CRITICAL**: Immediate security risks requiring urgent attention (e.g., public bucket policy)
- **HIGH**: Significant security risks (e.g., missing Block Public Access settings)
- **MEDIUM**: Important security considerations (e.g., lack of encryption)
- **LOW**: Best practice recommendations (e.g., missing access logs)

## Report Structure

The JSON report contains an array of issues, each with:

- **BucketName**: Name of the affected bucket
- **Issue**: Description of the security issue
- **Severity**: CRITICAL, HIGH, MEDIUM, or LOW
- **Details**: Additional context-specific information
- **Recommendation**: Suggested remediation (when applicable)

## Usage

To run the scanner, execute:

```bash
python3 scan/scan_s3.py
```

The scanner will:
1. Connect to AWS using your configured credentials
2. Scan all accessible S3 buckets
3. Display results in the terminal
4. Save a detailed JSON report to `scan/results/s3_scan_report.json`

## Requirements

- Python 3.6+
- boto3 library
- Properly configured AWS credentials with S3 read permissions

## Integration

This scanner is designed to work as part of the CloudSecVision security suite but can also be used independently for S3-specific security assessments.

## Best Practices

For optimal security posture, address all CRITICAL and HIGH severity findings immediately, followed by MEDIUM and LOW issues according to your organization's security requirements.
