```markdown
# IAM Security Scanner - Technical Reference

This document provides detailed technical information about the CloudSecVision IAM Security Scanner implementation.

## Architecture

The IAM scanner consists of several components:

1. **Policy Scanner**: Retrieves and examines IAM policies
2. **Permission Analyzer**: Evaluates policy permissions for security issues
3. **Report Generator**: Creates structured output of findings

## Implementation Details

### Module Structure

The IAM scanner is implemented in `scan/scan_iam.py` with the following core functions:

| Function | Description |
|----------|-------------|
| `scan_iam_permissions()` | Main function that orchestrates the scanning process |
| `is_policy_too_permissive()` | Evaluates if a policy document has overly permissive settings |

### Dependencies

- **boto3**: AWS SDK for Python, used for IAM API calls
- **json**: For parsing policy documents and generating reports
- **os**: For file path operations when saving reports

### API Reference

#### `scan_iam_permissions()`

Main entry point for scanning IAM permissions.

```python
def scan_iam_permissions():
    """
    Scans IAM policies for security issues and generates a report.
    
    Returns:
        list: A list of dictionaries containing policy issues
    """
```

This function:
1. Connects to AWS IAM service
2. Lists all attached policies
3. Retrieves each policy's document
4. Analyzes each policy for security issues
5. Generates and saves a JSON report
6. Returns the findings list

#### `is_policy_too_permissive(policy_doc)`

Analyzes a policy document for overly permissive configurations.

```python
def is_policy_too_permissive(policy_doc):
    """
    Determines if a policy document has overly permissive settings.
    
    Args:
        policy_doc (dict): The policy document to analyze
        
    Returns:
        bool: True if policy is too permissive, False otherwise
    """
```

This function evaluates policy statements for:
- Wildcard ("*") in Action
- Wildcard ("*") in Resource
- Combinations that create elevated risk

### Data Structures

#### Policy Issue Format

```json
{
  "PolicyName": "string",  // Name of the IAM policy
  "Arn": "string",         // ARN of the IAM policy
  "Issue": "string"        // Description of the security issue
}
```

## Performance Considerations

- The scanner only retrieves attached policies to minimize API calls
- Policy documents are cached after retrieval to improve performance
- Large AWS accounts may experience longer scan times due to API rate limiting

## Error Handling

The scanner handles several error conditions:

- Missing AWS credentials
- Insufficient permissions
- Malformed policy documents
- API throttling

Errors are logged with appropriate context to aid troubleshooting.

## Extending the Scanner

To extend the IAM scanner with additional checks:

1. Add new evaluation logic in `is_policy_too_permissive()` or create new analyzer functions
2. Update the results data structure to include new issue types
3. Modify the report generation to include new findings

## Integration Points

The IAM scanner integrates with:

- **AI Analyzer**: For generating recommendations based on findings
- **Dashboard**: For visualizing results in the web interface
- **Main Script**: For inclusion in comprehensive security scans
```
