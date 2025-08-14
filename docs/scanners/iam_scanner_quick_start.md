```markdown
# IAM Security Scanner - Quick Start Guide

This guide will help you quickly set up and use the IAM Security Scanner module of CloudSecVision.

## Prerequisites

Before using the IAM scanner, ensure you have:

1. AWS credentials configured (`~/.aws/credentials` or environment variables)
2. Appropriate IAM permissions to list and get policies
3. Python 3.8+ with boto3 installed

## Installation

The IAM scanner is included in the CloudSecVision package. If you haven't installed it yet:

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

Run the IAM scanner directly:

```bash
# From the project root directory
python3 -m scan.scan_iam
```

### Option 2: Using the Main Script

Use the main script with IAM flag:

```bash
# From the project root directory
python3 main.py --service iam
```

### Option 3: Using the Dashboard

1. Start the dashboard:
   ```bash
   ./run_dashboard.sh
   ```

2. Navigate to the IAM Analysis tab in the web interface
3. Click "Run IAM Scan" button

## Understanding the Results

After running the scan:

1. Results will be stored in `scan/results/iam_scan_report.json`
2. The number of issues found will be displayed in the terminal
3. In the dashboard, findings will be displayed with severity levels

## Example Output

```json
[
  {
    "PolicyName": "TestTooPermissivePolicy",
    "Arn": "arn:aws:iam::123456789012:policy/TestTooPermissivePolicy",
    "Issue": "Too permissive (\"*\" in Action or Resource)"
  }
]
```

## Next Steps

- Review the [Examples and Use Cases](iam_scanner_examples.md) for practical usage scenarios
- Check the [Technical Reference](iam_scanner_technical_reference.md) for API details
- Learn about integrating with AI analysis for advanced recommendations
```
