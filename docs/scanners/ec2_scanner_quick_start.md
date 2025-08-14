```markdown
# EC2 Security Scanner - Quick Start Guide

This guide will help you quickly set up and use the EC2 Security Scanner module of CloudSecVision.

## Prerequisites

Before using the EC2 scanner, ensure you have:

1. AWS credentials configured (`~/.aws/credentials` or environment variables)
2. Appropriate IAM permissions to describe security groups
3. Python 3.8+ with boto3 installed

## Installation

The EC2 scanner is included in the CloudSecVision package. If you haven't installed it yet:

```bash
# Clone the repository
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Running the Scanner

### Option 1: Using the Command Line

Run the EC2 scanner directly:

```bash
# From the project root directory
python3 -m scan.scan_ec2
```

### Option 2: Using the Main Script

Use the main script with EC2 flag:

```bash
# From the project root directory
python3 main.py --service ec2
```

### Option 3: Using the Dashboard

1. Start the dashboard:
   ```bash
   ./run_dashboard.sh
   ```

2. Navigate to the EC2 Analysis tab in the web interface
3. Click "Run EC2 Scan" button

## Understanding the Results

After running the scan:

1. Results will be stored in `scan/results/ec2_scan.json`
2. The number of issues found will be displayed in the terminal
3. In the dashboard, findings will be displayed with severity levels and recommendations

## Example Output

```json
[
  {
    "SecurityGroupId": "sg-0123456789abcdef0",
    "SecurityGroupName": "WebServerSG",
    "Issue": "SSH (port 22) exposed to the internet (0.0.0.0/0)",
    "Protocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRange": "0.0.0.0/0",
    "Severity": "HIGH"
  }
]
```

## Interpreting the Results

- **HIGH severity**: Critical issues that should be addressed immediately
- **MEDIUM severity**: Important issues that should be planned for remediation
- **LOW severity**: Minor issues that should be reviewed but may be acceptable in certain contexts

## Remediating Issues

Common remediation steps include:

1. Restricting security group rules to specific IP ranges
2. Implementing a bastion host or VPN for administrative access
3. Using security group references instead of CIDR blocks
4. Implementing just-in-time access for sensitive ports

## Next Steps

- Review the [Examples and Use Cases](ec2_scanner_examples.md) for practical usage scenarios
- Check the [Technical Reference](ec2_scanner_technical_reference.md) for API details
- Learn about integrating with AI analysis for advanced recommendations
```
