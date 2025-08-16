---
sidebar_position: 1
---

# CloudSecVision Documentation

Welcome to CloudSecVision, a comprehensive AWS security scanning tool with AI-powered analysis.

## What is CloudSecVision?

CloudSecVision is an advanced security assessment tool designed to identify vulnerabilities and misconfigurations in your AWS infrastructure. It combines automated scanning with AI-powered analysis to provide actionable security insights.

## Key Features

- **🔍 Multi-Service Scanning**: Comprehensive security assessment for IAM, EC2, and S3 services
- **🤖 AI-Powered Analysis**: Leverages Ollama for intelligent security report generation
- **📊 Interactive Dashboard**: Streamlit-based visualization for easy analysis
- **🎯 Actionable Insights**: Prioritized recommendations with step-by-step remediation
- **🚀 Easy Setup**: Simple installation and configuration process

## Quick Navigation

- [Getting Started](./getting-started) - Setup and installation guide
- [Scanner Overview](./scanners/overview) - Learn about the different security scanners
- [Dashboard Guide](./dashboard/overview) - Using the interactive dashboard
- [AI Analysis](./ai-analysis/overview) - Understanding AI-powered reports

## Architecture Overview

CloudSecVision is built with a modular architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Scanners      │    │   AI Analyzer   │    │   Dashboard     │
│                 │    │                 │    │                 │
│ • IAM Scanner   │───▶│ • Ollama        │───▶│ • Streamlit     │
│ • EC2 Scanner   │    │ • Report Gen    │    │ • Visualizations│
│ • S3 Scanner    │    │ • Recommendations│   │ • Metrics       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Getting Help

If you need help with CloudSecVision:

1. Check the [FAQ](./faq)
2. Browse the [Examples](./examples/overview)
3. Visit our [GitHub repository](https://github.com/Boualili-Youcef/cloudsecvision)

## Contributing

CloudSecVision is an open-source project. Contributions are welcome! See our [Contributing Guide](./contributing) for details.
