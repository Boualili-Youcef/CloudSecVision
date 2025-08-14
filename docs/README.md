```markdown
# CloudSecVision Documentation

Welcome to the CloudSecVision documentation. This folder contains comprehensive documentation for all security scanning modules in the CloudSecVision project.

## Available Documentation

### Scanner Modules

- [Security Scanners Overview](scanners/README.md) - Main documentation for all security scanners
  - [IAM Security Scanner](scanners/iam_scanner_documentation.md) - Documentation for the IAM policy security scanner
  - [EC2 Security Scanner](scanners/ec2_scanner_documentation.md) - Documentation for the EC2 security group scanner
  - [S3 Security Scanner](scanners/s3_scanner_documentation.md) - Documentation for the S3 bucket security scanner

## About CloudSecVision

CloudSecVision is a comprehensive cloud security scanning and visualization tool designed to identify security vulnerabilities and misconfigurations in AWS environments. The project aims to provide actionable security insights with minimal setup.

## Getting Started

Each scanner module has its own documentation with specific setup and usage instructions. Please refer to the individual scanner documentation for details.

## Technical Documentation

- [Architecture and Design](architecture.md) - Comprehensive overview of the project architecture
- [Developer Guide](developer_guide.md) - Guide for developers contributing to the project
- [Ollama Integration](ollama_integration.md) - Detailed information about the AI integration

## Project Structure

CloudSecVision is organized into several components:

- `scan/` - Security scanning modules for different AWS services
- `analysis/` - Analysis tools for processing scan results
- `dashboard.py` - Visualization dashboard for security findings
- `docs/` - Comprehensive documentation
- `test/` - Test suite for the project

## License

CloudSecVision is distributed under the terms of the license included in the project repository.

## Contributing

For information on contributing to CloudSecVision documentation, please refer to the developer guide and project's contribution guidelines.
