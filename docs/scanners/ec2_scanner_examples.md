```markdown
# EC2 Security Scanner - Examples and Use Cases

This document provides practical examples and common use cases for the EC2 Security Scanner in CloudSecVision.

## Basic Usage Examples

### 1. Standalone Command Line Scan

Run a quick EC2 security group scan from the command line:

```bash
# Navigate to the project directory
cd cloudsecvision

# Run the EC2 scanner module
python3 -m scan.scan_ec2
```

Output:
```
✅ EC2 report generated at scan/results/ec2_scan.json (3 issues found)
```

### 2. Integration with Main Script

Run the EC2 scanner as part of a comprehensive security assessment:

```bash
# Run only EC2 scanner
python3 main.py --service ec2

# Run EC2 scanner with AI analysis
python3 main.py --service ec2 --ai
```

### 3. Dashboard Integration

```python
# From dashboard.py
from scan.scan_ec2 import scan_ec2_security_groups
from analysis.ai_analyzer import generate_ec2_report

# Run scan
ec2_results = scan_ec2_security_groups()

# Generate AI report
ec2_analysis = generate_ec2_report(ec2_results)
```

## Common Use Cases

### 1. Security Compliance Check

**Scenario**: Verify EC2 security groups comply with security best practices before an audit.

**Implementation**:
```python
# Run scan and check results
ec2_issues = scan_ec2_security_groups()

# Check for high severity issues
high_severity_issues = [issue for issue in ec2_issues if issue.get('Severity') == 'HIGH']

if high_severity_issues:
    print("⚠️ Found high severity EC2 security issues:")
    for issue in high_severity_issues:
        sg_name = issue.get('SecurityGroupName', 'Unnamed')
        sg_id = issue.get('SecurityGroupId', 'Unknown')
        print(f"  - {sg_name} ({sg_id}): {issue['Issue']}")
    print("\nRemediation required before compliance approval.")
else:
    print("✅ No high severity EC2 security group issues found.")
```

### 2. DevOps Pipeline Integration

**Scenario**: Automated security scanning as part of CI/CD pipeline for infrastructure-as-code.

```bash
#!/bin/bash
# CI/CD Script for Infrastructure Security

# Clone repository
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision

# Setup environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run security scan after Terraform apply
terraform apply -auto-approve
python3 -m scan.scan_ec2

# Check for critical issues
if grep -q "HIGH" scan/results/ec2_scan.json; then
  echo "PIPELINE FAILED: Critical EC2 security issues detected"
  # Optionally roll back the changes
  # terraform destroy -auto-approve
  exit 1
else
  echo "EC2 security check passed"
fi
```

### 3. Continuous Security Monitoring

**Scenario**: Daily security audit of EC2 security groups with alert notifications.

**Implementation using cron job**:
```bash
# /etc/cron.daily/ec2-security-scan
#!/bin/bash

cd /path/to/cloudsecvision
source venv/bin/activate

# Run scan
python3 main.py --service ec2

# Check for new issues
NEW_ISSUES=$(diff -q scan/results/ec2_scan.json.previous scan/results/ec2_scan.json 2>/dev/null)

if [ -n "$NEW_ISSUES" ] || [ ! -f scan/results/ec2_scan.json.previous ]; then
  # Send alert via Slack webhook
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠️ New EC2 security issues detected. Check the dashboard for details.\"}" \
    https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
    
  # Backup current results for next comparison
  cp scan/results/ec2_scan.json scan/results/ec2_scan.json.previous
fi
```

## Advanced Examples

### 1. Custom Security Group Rule Evaluation

Extend the scanner with custom rule evaluation logic:

```python
def check_for_sensitive_ports(security_group):
    """Check for additional sensitive ports exposed to the internet"""
    sensitive_ports = {
        5601: "Kibana",
        8080: "Web Proxy",
        8443: "Web Services",
        4444: "WebDriver",
        9090: "Prometheus",
        9000: "SonarQube",
        2375: "Docker API",
        2376: "Docker API TLS"
    }
    
    issues = []
    
    for permission in security_group.get('IpPermissions', []):
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        
        if from_port is None or to_port is None:
            continue
            
        for port, service in sensitive_ports.items():
            if from_port <= port <= to_port:
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr == '0.0.0.0/0':
                        issues.append({
                            'SecurityGroupId': security_group['GroupId'],
                            'SecurityGroupName': security_group.get('GroupName', ''),
                            'Issue': f"{service} port ({port}) exposed to the internet ({cidr})",
                            'Protocol': permission.get('IpProtocol'),
                            'FromPort': from_port,
                            'ToPort': to_port,
                            'IpRange': cidr,
                            'Severity': 'HIGH'
                        })
                        
    return issues
```

### 2. Integration with Cloud Security Posture Management

```python
import json
import requests
from scan.scan_ec2 import scan_ec2_security_groups

# Run EC2 security scan
ec2_issues = scan_ec2_security_groups()

# Format for CSPM ingestion
cspm_findings = []
for issue in ec2_issues:
    cspm_findings.append({
        "findingType": "AWS_EC2_SECURITY_GROUP",
        "resourceId": issue["SecurityGroupId"],
        "resourceName": issue.get("SecurityGroupName", ""),
        "region": "us-east-1",  # Replace with actual region
        "severity": issue.get("Severity", "MEDIUM"),
        "description": issue["Issue"],
        "remediation": "Restrict security group rules to specific IP ranges.",
        "complianceStandards": ["CIS-AWS-4.1", "NIST-800-53"]
    })

# Send to CSPM API
response = requests.post(
    "https://cspm.example.com/api/findings",
    headers={"Authorization": "Bearer TOKEN", "Content-Type": "application/json"},
    data=json.dumps(cspm_findings)
)
```

## Troubleshooting Examples

### 1. Handling Cross-Region Scanning

```python
import boto3
from concurrent.futures import ThreadPoolExecutor

def scan_ec2_all_regions():
    """Scan EC2 security groups across all regions"""
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    all_results = []
    
    def scan_region(region):
        print(f"Scanning {region}...")
        try:
            regional_ec2 = boto3.client('ec2', region_name=region)
            security_groups = regional_ec2.describe_security_groups()['SecurityGroups']
            
            results = []
            for sg in security_groups:
                # Your scanning logic here
                # ...
                
            return {"region": region, "results": results}
        except Exception as e:
            return {"region": region, "error": str(e)}
    
    # Scan regions in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        scan_results = list(executor.map(scan_region, regions))
    
    # Process results
    for result in scan_results:
        if "error" in result:
            print(f"Error scanning {result['region']}: {result['error']}")
        else:
            all_results.extend(result["results"])
            print(f"Found {len(result['results'])} issues in {result['region']}")
    
    return all_results
```

### 2. Correlating EC2 Instances with Security Groups

```python
def get_instances_by_security_group(security_group_id):
    """Find all EC2 instances using a specific security group"""
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(
        Filters=[{'Name': 'instance.group-id', 'Values': [security_group_id]}]
    )
    
    instances = []
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instances.append({
                'InstanceId': instance['InstanceId'],
                'State': instance['State']['Name'],
                'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                'Tags': instance.get('Tags', [])
            })
    
    return instances

# Usage example
def analyze_security_group_impact(security_group_id):
    """Analyze impact of a vulnerable security group"""
    affected_instances = get_instances_by_security_group(security_group_id)
    
    print(f"Security Group {security_group_id} affects {len(affected_instances)} instances:")
    for instance in affected_instances:
        name = next((tag['Value'] for tag in instance['Tags'] if tag['Key'] == 'Name'), 'Unnamed')
        print(f"  - {name} ({instance['InstanceId']}): {instance['PublicIpAddress']}")
```
```
