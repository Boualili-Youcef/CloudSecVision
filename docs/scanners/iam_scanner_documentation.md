```markdown
# IAM Security Scanner - Documentation

## Overview

The CloudSecVision IAM Security Scanner is designed to identify risky Identity and Access Management (IAM) configurations in your AWS environment. This module focuses on identifying overly permissive policies that could pose security risks to your organization.

## Core Functionalities

### Policy Scanning

The IAM scanner examines all attached policies in the AWS account to identify those that:

1. **Use wildcard permissions**: Policies that include `"Action": "*"` or similar wildcards
2. **Target all resources**: Policies that specify `"Resource": "*"`
3. **Lack proper constraints**: Policies missing condition elements for sensitive operations

### Security Analysis

Each identified policy is analyzed for:

- **Scope of permissions**: How broad the permissions are
- **Service impact**: Which AWS services are affected
- **Risk level**: Assigned based on potential security impact

### Report Generation

The scanner produces a JSON-formatted report with:
- Policy name and ARN
- Issue description
- Severity level
- Recommended remediation steps

## Integration with AI Analysis

The IAM Scanner integrates with CloudSecVision's AI analysis system to:

1. Provide detailed explanations of security issues
2. Generate remediation recommendations
3. Assess overall account security posture
4. Format findings for better comprehension

## Implementation Details

### Scanning Method

The scanner uses AWS SDK (boto3) to:
1. List all policies attached to IAM entities
2. Retrieve the default version of each policy
3. Analyze the policy document for security concerns

### Detection Logic

Policies are flagged as overly permissive if they:
- Use `"*"` in the Action element
- Use `"*"` in the Resource element without constraining conditions
- Combine sensitive service permissions without proper segregation

## Usage

### Basic Invocation

```python
from scan.scan_iam import scan_iam_permissions

# Run the scan
results = scan_iam_permissions()
```

### Output Example

```json
[
  {
    "PolicyName": "AdminAccessPolicy",
    "Arn": "arn:aws:iam::123456789012:policy/AdminAccessPolicy",
    "Issue": "Too permissive (\"*\" in Action or Resource)"
  }
]
```

## Best Practices

- Run the IAM scanner regularly as part of security checks
- Review and remediate all identified issues
- Use least-privilege approach when creating new policies
- Implement AWS Organizations Service Control Policies (SCPs) for additional guardrails

## Limitations

- Focuses primarily on attached policies (not inline policies)
- Does not analyze dynamic policy conditions in depth
- Does not evaluate permissions boundaries
```
