```markdown
# EC2 Security Scanner - Technical Reference

This document provides detailed technical information about the CloudSecVision EC2 Security Scanner implementation.

## Architecture

The EC2 Security Group scanner consists of several components:

1. **Security Group Collector**: Retrieves all security groups from AWS
2. **Rule Analyzer**: Examines security group rules for potential security issues
3. **Report Generator**: Creates structured output of findings

## Implementation Details

### Module Structure

The EC2 scanner is implemented in `scan/scan_ec2.py` with the following core function:

| Function | Description |
|----------|-------------|
| `scan_ec2_security_groups()` | Main function that orchestrates the scanning process |

### Dependencies

- **boto3**: AWS SDK for Python, used for EC2 API calls
- **json**: For generating structured reports
- **os**: For file path operations when saving reports

### API Reference

#### `scan_ec2_security_groups()`

Main entry point for scanning EC2 security groups.

```python
def scan_ec2_security_groups():
    """
    Scans EC2 security groups for security issues and generates a report.
    
    Returns:
        list: A list of dictionaries containing security group issues
    """
```

This function:
1. Connects to AWS EC2 service
2. Lists all security groups
3. Analyzes each security group's ingress and egress rules
4. Identifies potential security issues
5. Generates and saves a JSON report
6. Returns the findings list

### Rule Analysis Logic

The scanner analyzes security group rules using the following criteria:

1. **SSH Exposure**: Identifies security groups that allow SSH (port 22) from public IP ranges (0.0.0.0/0 or ::/0)
2. **Administrative Ports**: Checks for sensitive ports exposed to the internet:
   - 3389 (RDP)
   - 1433, 1434 (SQL Server)
   - 3306 (MySQL/MariaDB)
   - 5432 (PostgreSQL)
   - 27017, 27018 (MongoDB)
   - 9200, 9300 (Elasticsearch)
   - 6379 (Redis)
3. **Broad Port Ranges**: Identifies rules that allow access to wide port ranges from public IP addresses
4. **Protocol Issues**: Flags rules that allow all protocols (-1) from public IP ranges

### Data Structures

#### Security Group Issue Format

```json
{
  "SecurityGroupId": "string",     // ID of the security group
  "SecurityGroupName": "string",   // Name of the security group
  "Issue": "string",               // Description of the security issue
  "Protocol": "string",            // Protocol (tcp, udp, icmp, etc.)
  "FromPort": number,              // Start port in the range
  "ToPort": number,                // End port in the range
  "IpRange": "string",             // CIDR range with access
  "Severity": "string"             // HIGH, MEDIUM, or LOW
}
```

## Performance Considerations

- The scanner uses the `describe_security_groups` API call, which returns all security groups in a single request
- For accounts with many security groups, the analysis is performed in-memory to avoid additional API calls
- The performance is typically limited by the number of security groups and rules to analyze, not by API rate limiting

## Error Handling

The scanner handles several error conditions:

- Missing AWS credentials
- Insufficient permissions
- API throttling
- Region availability issues

Errors are logged with appropriate context to aid troubleshooting.

## Extending the Scanner

To extend the EC2 scanner with additional checks:

1. Modify the scan function to include new rule evaluations
2. Update the results data structure to include new issue types
3. Add new severity classifications for different types of findings

Example for adding a new check:

```python
# Check for database ports exposed to internet
if from_port <= 3306 <= to_port and ip_protocol == 'tcp':
    for ip_range in permission.get('IpRanges', []):
        cidr = ip_range.get('CidrIp')
        if cidr == '0.0.0.0/0':
            results.append({
                'SecurityGroupId': sg_id,
                'SecurityGroupName': sg_name,
                'Issue': f"MySQL/MariaDB (port 3306) exposed to the internet ({cidr})",
                'Protocol': ip_protocol,
                'FromPort': from_port,
                'ToPort': to_port,
                'IpRange': cidr,
                'Severity': 'HIGH'
            })
```

## Integration Points

The EC2 scanner integrates with:

- **AI Analyzer**: For generating recommendations based on findings
- **Dashboard**: For visualizing results in the web interface
- **Main Script**: For inclusion in comprehensive security scans
```
