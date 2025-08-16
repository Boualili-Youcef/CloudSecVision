---
sidebar_position: 2
---

# Getting Started

This guide will help you set up and start using CloudSecVision in just a few minutes.

## Prerequisites

Before installing CloudSecVision, ensure you have:

### System Requirements

- **Python 3.8+** - CloudSecVision is built with Python
- **Node.js 18+** - Required for the documentation site
- **Git** - For cloning the repository

### AWS Requirements

- **AWS Account** - Active AWS account with resources to scan
- **AWS CLI** - Configured with appropriate credentials
- **IAM Permissions** - Sufficient permissions for the services you want to scan

### Required IAM Permissions

Your AWS credentials need the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketLifecycleConfiguration",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision
```

### Step 2: Set Up Python Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Configure AWS Credentials

```bash
# Option 1: Using AWS CLI
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

### Step 4: (Optional) Set Up Ollama for AI Analysis

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# In another terminal, pull a model
ollama pull llama2
```

## Quick Start

### Option 1: Run Individual Scanners

```bash
# Scan IAM policies
python -m scan.scan_iam

# Scan EC2 security groups
python -m scan.scan_ec2

# Scan S3 buckets
python -m scan.scan_s3
```

### Option 2: Run All Scanners

```bash
# Run all scanners
python main.py --service all

# Run with AI analysis (requires Ollama)
python main.py --service all --ai
```

### Option 3: Use the Dashboard

```bash
# Launch the interactive dashboard
./run_dashboard.sh
```

The dashboard will be available at: `http://localhost:8501`

## Verification

To verify your installation:

1. **Check AWS connectivity**:
   ```bash
   aws sts get-caller-identity
   ```

2. **Test a scanner**:
   ```bash
   python -m scan.scan_iam
   ```

3. **Check results**:
   ```bash
   ls scan/results/
   ```

## Next Steps

Now that CloudSecVision is installed:

1. [Learn about the different scanners](./scanners/overview)
2. [Explore the dashboard features](./dashboard/overview)
3. [Set up AI analysis](./ai-analysis/setup)
4. [Review security best practices](./best-practices)

## Troubleshooting

### Common Issues

**AWS Credentials Error**
```
NoCredentialsError: Unable to locate credentials
```
**Solution**: Ensure AWS credentials are properly configured using `aws configure` or environment variables.

**Permission Denied Error**
```
AccessDenied: User is not authorized to perform: iam:ListPolicies
```
**Solution**: Verify your IAM user has the required permissions listed above.

**Ollama Connection Error**
```
Connection refused: Ollama service not running
```
**Solution**: Start the Ollama service with `ollama serve` in a separate terminal.

### Getting Help

If you encounter issues:

1. Check the [FAQ](./faq)
2. Review the [Troubleshooting Guide](./troubleshooting)
3. Open an issue on [GitHub](https://github.com/Boualili-Youcef/cloudsecvision/issues)
