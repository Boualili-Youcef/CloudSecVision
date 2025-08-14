# S3 Security Scanner - Technical Reference

## Code Structure

```
scan_s3.py
├── class S3SecurityScanner
│   ├── __init__()
│   ├── list_buckets()
│   ├── check_bucket_public_access()
│   ├── check_bucket_encryption()
│   ├── check_bucket_versioning()
│   ├── check_bucket_logging()
│   ├── check_bucket_lifecycle()
│   └── scan_bucket_comprehensive()
└── main()
```

## Class Methods Details

### S3SecurityScanner.__init__()

```python
def __init__(self):
    self.s3 = boto3.client('s3')
    self.results = []
```

- Creates a boto3 S3 client using default credential configuration
- Initializes empty results list

### S3SecurityScanner.list_buckets()

```python
def list_buckets(self):
    """List all S3 buckets in the account"""
    try:
        response = self.s3.list_buckets()
        return [bucket['Name'] for bucket in response['Buckets']]
    except Exception as e:
        print(f"Error listing buckets: {e}")
        return []
```

- Uses the S3 client's list_buckets() API call
- Extracts just the bucket names from the response
- Handles exceptions gracefully and returns an empty list on error

### S3SecurityScanner.check_bucket_public_access()

This method performs three levels of public access checks:

1. **Block Public Access Settings**:
   - Verifies all four Block Public Access settings are enabled
   - CRITICAL severity if missing entirely
   - HIGH severity if partially configured

2. **ACL Checks**:
   - Examines bucket ACLs for public grants
   - CRITICAL severity for AllUsers grants
   - HIGH severity for AuthenticatedUsers grants

3. **Bucket Policy Analysis**:
   - Checks for policy statements with public principals
   - CRITICAL severity for Principal: "*" configurations

### S3SecurityScanner.check_bucket_encryption()

Verifies server-side encryption:
- HIGH severity if no encryption configured
- MEDIUM severity if weak algorithm detected
- Checks specifically for AES256 and aws:kms algorithms

### S3SecurityScanner.check_bucket_versioning()

Examines versioning configuration:
- MEDIUM severity if versioning not enabled
- MEDIUM severity if MFA Delete not enabled
- Provides specific recommendations for each issue

### S3SecurityScanner.check_bucket_logging()

Verifies access logging:
- LOW severity if logging not configured
- Includes recommendation to enable logging for audit trails

### S3SecurityScanner.check_bucket_lifecycle()

Checks lifecycle policy configuration:
- LOW severity if no lifecycle policy found
- Includes recommendation for cost optimization

### S3SecurityScanner.scan_bucket_comprehensive()

Central method that:
1. Calls all check methods for a bucket
2. Collects statistics on bucket contents
3. Categorizes issues by severity
4. Provides console output for visibility
5. Returns all issues for reporting

## Exception Handling

The scanner handles various AWS API exceptions:
- NoSuchPublicAccessBlockConfiguration
- NoSuchBucketPolicy
- ServerSideEncryptionConfigurationNotFoundError
- NoSuchLifecycleConfiguration
- General ClientError exceptions

Each exception is captured and translated into appropriate findings rather than causing scanner failure.

## Report Output Format

Sample JSON structure for a finding:

```json
{
  "BucketName": "example-bucket",
  "Issue": "Block Public Access not fully configured",
  "Severity": "HIGH",
  "Details": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": false,
    "RestrictPublicBuckets": false
  },
  "Recommendation": "Enable all Block Public Access settings"
}
```

## AWS API Calls Used

The scanner uses the following AWS API calls:
- `list_buckets`
- `get_public_access_block`
- `get_bucket_acl`
- `get_bucket_policy`
- `get_bucket_encryption`
- `get_bucket_versioning`
- `get_bucket_logging`
- `get_bucket_lifecycle_configuration`
- `list_objects_v2`

## Performance Considerations

- The scanner makes multiple API calls per bucket
- For accounts with many buckets, the scan may take significant time
- Object count is sampled with MaxKeys=10 to avoid long operations

## Limitations

- Only samples object counts (does not perform full object enumeration)
- Does not analyze individual object permissions
- Only checks bucket-level configurations
- Cannot detect cross-account access issues
- Limited to the permissions of the provided AWS credentials
