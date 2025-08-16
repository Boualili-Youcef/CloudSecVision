# 🛡️ CloudSecVision - AWS Security Scanner with AI Analysis

Comprehensive security scanner for AWS infrastructure with AI-powered analysis using Ollama.

## 📋 Table of Contents

- [🎯 Introduction](#-introduction)
- [🚀 Quick Start (5 min)](#-quick-start-5-min)
- [📖 Complete Documentation](#-complete-documentation)
- [🔍 Features](#-features)
- [📜 License](#-license)

## 🎯 Introduction

CloudSecVision is an advanced AWS security scanning tool that combines automated analysis with artificial intelligence to identify security risks in your AWS infrastructure.

**Available Scanners:**
- **IAM**: Policy analysis to detect excessive privileges
- **S3**: Public exposure verification and configuration checks
- **EC2**: Security group analysis and permissive rules detection

## 🚀 Quick Start (5 min)

```bash
# Clone the repository
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision

# Environment setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# AWS configuration
aws configure

# Launch the dashboard
./run_dashboard.sh
```

✅ **Dashboard accessible at:** `http://localhost:8502`

## 📖 Complete Documentation

### 🌐 Docusaurus Documentation Site

Complete and interactive documentation is available with Docusaurus:

```bash
# Launch the documentation
cd website
npm install
npm start
```

✅ **Documentation accessible at:** `http://localhost:3000/cloudsecvision/`

The documentation includes:
- **Detailed guides** for each scanner (IAM, S3, EC2)
- **Ollama configuration** for AI analysis
- **Technical architecture** of the project
- **Developer guide** and contribution
- **FAQ and troubleshooting**
- **Practical usage examples**

### 📁 Local Documentation

You can also browse the documentation directly in the `website/docs/` folder:
- Installation and configuration
- Detailed usage guides
- Technical reference
- Best practices

## 🔍 Features

### 🔐 Security Scanners
- **IAM Scanner**: Detects wildcard permissions and excessive privileges
- **S3 Scanner**: Identifies public buckets and encryption issues
- **EC2 Scanner**: Analyzes overly permissive security rules

### 🤖 AI Analysis with Ollama
- **Automated severity assessment** of vulnerabilities
- **Personalized recommendations** to fix issues
- **Compliance analysis** against best practices
- **Executive reports** with action prioritization

### 📊 Interactive Dashboard
- **Intuitive web interface** with Streamlit
- **Results visualization** by service
- **Automated AI report generation**
- **Security metrics tracking**

### 💻 Command Line Usage
```bash
# Scan a specific service
python main.py --service iam
python main.py --service s3  
python main.py --service ec2

# Launch the web interface
./run_dashboard.sh
```

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Developed by Youcef BOUALILI** - M1 Cloud Security & AWS Project

