# 🛡## 📋 Table of Contents

- [🎯 Introduction](#-introduction)
- [🚀 Quick Start](#-quick-start)
- [📖 Documentation](#-documentation)
- [🔍 Security Scanners](#-security-scanners)
- [🧠 AI Analysis](#-ai-analysis)
- [📊 Dashboard Features](#-dashboard-features)
- [🛡️ Security Considerations](#️-security-considerations)
- [📜 License](#-license)on - AWS Security Scanner with AI Analysis

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

## 🚀 Quick Start

Get started with CloudSecVision in just a few minutes:

```bash
# Clone the repository
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure

# Launch the dashboard
./run_dashboard.sh
```

The dashboard will be accessible at: `http://localhost:8502`

For detailed setup instructions, see the [Installation Guide](docs/installation.md).

## � Documentation

Comprehensive documentation is available in the `docs/` folder:

- **[Getting Started](docs/getting-started.md)** - Overview and introduction
- **[Quick Start Guide](docs/quick-start.md)** - Get running in 5 minutes
- **[Installation Guide](docs/installation.md)** - Complete setup instructions
- **[Scanner Documentation](docs/scanners/)** - Detailed scanner information
  - [IAM Scanner](docs/scanners/iam_scanner_readme.md)
  - [S3 Scanner](docs/scanners/s3_scanner_readme.md)
  - [EC2 Scanner](docs/scanners/ec2_scanner_readme.md)
- **[AI Integration](docs/ollama_integration.md)** - Ollama setup and usage
- **[Architecture](docs/architecture.md)** - Technical architecture details
- **[Developer Guide](docs/developer_guide.md)** - Contributing and development

## 🔍 Security Scanners

CloudSecVision includes three main security scanners:

### IAM Scanner
- Analyzes IAM policies for overprivileged access
- Detects wildcard permissions and excessive privileges
- Validates adherence to least privilege principle

### S3 Scanner  
- Checks for public bucket exposures
- Validates encryption and versioning settings
- Reviews access logging and lifecycle policies

### EC2 Scanner
- Analyzes security group configurations
- Identifies overly permissive rules
- Detects unrestricted access from 0.0.0.0/0

**Usage:**
```bash
# Run individual scanners
python main.py --service iam
python main.py --service s3
python main.py --service ec2

# Or use the interactive dashboard
./run_dashboard.sh
```

For detailed scanner documentation, see [Scanner Documentation](docs/scanners/).

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

## 📊 Dashboard Features

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

## 🛡️ Security Considerations

- **AWS Credentials**: Store AWS credentials securely and follow the principle of least privilege
- **Scan Results**: Handle scan results confidentially as they contain sensitive security information
- **Network Considerations**: Be aware that scanning uses AWS API calls which may appear in CloudTrail logs
- **Resource Usage**: Be mindful of API rate limits when scanning large environments

For complete installation instructions and configuration details, see our [Documentation](docs/).

## � License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Developed by Youcef** - M1 Cloud Security & AWS Project
