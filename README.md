# 🛡️ CloudSecVision - AWS Security Scanner with AI Analysis

A comprehensive security scanner for AWS infrastructure with AI-powered analysis using Ollama.

## 📋 Table of Contents

- [🎯 Introduction](#-introduction)
- [⚙️ Prerequisites](#️-prerequisites)
- [🚀 Installation](#-installation)
- [🔧 AWS Configuration](#-aws-configuration)
- [🤖 Ollama Setup](#-ollama-setup)
- [📝 Usage](#-usage)
- [🔍 Security Scanners](#-security-scanners)
- [🧠 AI Analysis](#-ai-analysis)
- [📊 Dashboard](#-dashboard)
- [�️ Best Practices](#️-best-practices)
- [� Security Considerations](#-security-considerations)
- [📜 License](#-license)

## 🎯 Introduction

CloudSecVision is an advanced AWS security scanning tool that combines automated scanning with AI-powered analysis to identify security risks in your AWS infrastructure. The project supports scanning IAM policies, EC2 security groups, and S3 bucket configurations to ensure they follow security best practices.

## ⚙️ Prerequisites

- Python 3.8+ installed on your system
- AWS account with appropriate access permissions
- Access to IAM, EC2, and/or S3 services for testing
- AWS credentials (Access Key ID and Secret Access Key)
- At least 4GB of RAM for running the Ollama models

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

This will install all required packages including:
- `boto3` for AWS API access
- `streamlit` for the dashboard interface
- `openai` for AI analysis interfaces
- `requests` for API communication
- `plotly` and `pandas` for data visualization

## 🔧 AWS Configuration

### Setting up AWS Credentials

1. Log in to the AWS Management Console
2. Navigate to **IAM > Users**
3. Select your user or create a new one with appropriate permissions
4. In the **Security credentials** tab, click **Create access key**
5. Note down the generated Access Key ID and Secret Access Key

### Configure AWS CLI
```bash
aws configure
```

Enter the requested information:
- **AWS Access Key ID**: your access key
- **AWS Secret Access Key**: your secret key
- **Default region name**: your preferred region (e.g., us-east-1)
- **Default output format**: json

Alternatively, you can create `~/.aws/credentials` and `~/.aws/config` files manually.

### Required IAM Permissions

The following permissions are required to run all scanners:
- `s3:ListAllMyBuckets`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`
- `s3:GetBucketEncryption`
- `s3:GetBucketVersioning`
- `s3:GetBucketLogging`
- `s3:GetBucketLifecycleConfiguration`
- `ec2:DescribeSecurityGroups`
- `iam:ListPolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`

## 🤖 Ollama Setup

CloudSecVision uses Ollama to provide AI-powered analysis of security scan results.

### 1. Install Ollama
Download and install Ollama from the official website: [https://ollama.com](https://ollama.com)

### 2. Start Ollama server
```bash
ollama serve
```

### 3. Pull the recommended model
```bash
ollama pull llama3.2:3b
```

The 3B model (approximately 2GB) provides a good balance between performance and resource usage. If you have more resources available, you can use larger models like:
```bash
ollama pull llama3.2:8b
```

## 📝 Usage

### Running the Dashboard

Use the provided script to launch the Streamlit dashboard:

```bash
./run_dashboard.sh
```

If you encounter permission issues:
```bash
chmod +x run_dashboard.sh
./run_dashboard.sh
```

The dashboard will be accessible at: `http://localhost:8501`

### Running Individual Scanners

You can also run individual scanners from the command line:

```bash
# S3 Scanner
python -m scan.scan_s3

# EC2 Security Groups Scanner
python -m scan.scan_ec2

# IAM Policies Scanner
python -m scan.scan_iam
```

## 🔍 Security Scanners

### S3 Scanner
The S3 scanner performs comprehensive security checks on all S3 buckets in your account:

- **Public Access Checks**: Identifies buckets with public access through ACLs or policies
- **Block Public Access Settings**: Verifies proper configuration of Block Public Access settings
- **Encryption**: Checks for default encryption and validates encryption settings
- **Versioning**: Verifies if versioning is enabled for data protection
- **MFA Delete**: Checks if MFA Delete is enabled for additional protection
- **Logging**: Validates if access logging is properly configured
- **Lifecycle Policies**: Checks for appropriate lifecycle policies

### EC2 Scanner
The EC2 scanner analyzes security groups for risky configurations:

- **SSH Access**: Identifies security groups allowing SSH (port 22) access from the internet (0.0.0.0/0)
- **Unrestricted Ports**: Detects security groups with overly permissive access
- **IPv6 Security**: Checks for insecure IPv6 rules

### IAM Scanner
The IAM scanner evaluates IAM policies for overly permissive configurations:

- **Wildcard Permissions**: Identifies policies using wildcards (*) in Action or Resource fields
- **Policy Scope**: Analyzes the scope of policies to identify excessive permissions
- **Principle of Least Privilege**: Validates adherence to the principle of least privilege

## 🧠 AI Analysis

CloudSecVision uses Ollama to provide intelligent analysis of security findings:

1. **Severity Assessment**: AI determines the severity of security issues
2. **Risk Impact Analysis**: Detailed analysis of potential impact of security issues
3. **Compliance Evaluation**: Assessment of compliance status against best practices
4. **Actionable Recommendations**: Prioritized list of actions to address security concerns
5. **Technical Explanations**: Detailed explanations of why issues pose security risks

The AI analysis provides:
- **Executive Summary**: Concise overview of security posture
- **Risk Level**: Critical, High, Medium, or Low
- **Detailed Analysis**: In-depth explanation of security issues
- **Recommendations**: Specific actions to improve security
- **Priority Actions**: Immediate steps with recommended timeframes
- **Compliance Status**: Compliance evaluation against best practices

## 📊 Dashboard

The CloudSecVision dashboard provides a user-friendly interface to:

1. **Run Scans**: Execute scans for S3, EC2, and IAM services
2. **View Results**: See detailed scan results with severity indicators
3. **Generate AI Reports**: Create comprehensive security analysis reports
4. **Track Issues**: Monitor security issues across services
5. **Visualize Data**: View security metrics and statistics

The dashboard includes dedicated pages for each AWS service:
- **Overview**: High-level summary of all security findings
- **S3 Analysis**: Detailed analysis of S3 bucket security
- **EC2 Analysis**: Security evaluation of EC2 security groups
- **IAM Analysis**: Assessment of IAM policy permissions

## 🛡️ Best Practices

When using CloudSecVision:

1. **Run in a secure environment**: Execute scans from a secure workstation
2. **Regular scanning**: Schedule regular security scans
3. **Review AI recommendations**: Always review AI-generated recommendations before implementation
4. **Address critical issues first**: Focus on critical and high-severity issues
5. **Document exceptions**: Document any intentional exceptions to security best practices
6. **Follow remediation steps**: Implement recommended security improvements

## 🔒 Security Considerations

- **AWS Credentials**: Store AWS credentials securely and follow the principle of least privilege
- **Scan Results**: Handle scan results confidentially as they contain sensitive security information
- **Network Considerations**: Be aware that scanning uses AWS API calls which may appear in CloudTrail logs
- **Resource Usage**: Be mindful of API rate limits when scanning large environments

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

### Main Code
```python
import boto3

def list_buckets():
    """Retrieves the list of all S3 buckets"""
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    return [bucket['Name'] for bucket in response['Buckets']]

def check_bucket_public(bucket_name):
    """Checks if a bucket is publicly accessible"""
    s3 = boto3.client('s3')
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if 'AllUsers' in grant['Grantee'].get('URI', ''):
                return True
        return False
    except Exception as e:
        print(f"Error checking {bucket_name}: {e}")
        return False

def main():
    """Main function"""
    print("Script started")
    buckets = list_buckets()
    print(f"🌐 Buckets detected: {len(buckets)}")
    
    for bucket in buckets:
        if check_bucket_public(bucket):
            print(f"🚨 Public bucket found: {bucket}")
        else:
            print(f"✅ Private bucket: {bucket}")

if __name__ == "__main__":
    main()
```

## 📊 Project Structure

```
cloudsecvision/
├── src/
│   └── s3_scanner.py
├── README.md
├── requirements.txt
├── aws/
├── config/
├── data/
├── docs/
└── test/
```

## 🔒 Best Practices

- **Key Security**: Never expose your access keys in code or repositories
- **Least Privilege Principle**: Use minimal IAM rights necessary
- **Avoid Public Access**: Only allow public access when strictly necessary
- **Key Rotation**: Automate regular rotation of access keys
- **Monitoring**: Monitor security with AWS Config, Trusted Advisor, and CloudTrail

### Minimum Required IAM Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🛡️ Security

This script only performs read operations and does not modify any configuration of your S3 buckets. It is designed to be a non-intrusive audit tool.

---

**Developed by Youcef** - M1 Cloud Security & AWS Project
