---
sidebar_position: 8
---

# FAQ

Frequently Asked Questions about CloudSecVision.

## General Questions

### What is CloudSecVision?

CloudSecVision is a comprehensive AWS security scanning tool that combines automated security assessments with AI-powered analysis. It helps organizations identify vulnerabilities and misconfigurations in their AWS infrastructure across IAM, EC2, and S3 services.

### Is CloudSecVision free to use?

Yes, CloudSecVision is an open-source project released under the MIT license. You can use, modify, and distribute it freely.

### What AWS services does CloudSecVision support?

Currently, CloudSecVision supports:
- **IAM (Identity and Access Management)**: Policy analysis and permission auditing
- **EC2 (Elastic Compute Cloud)**: Security group configuration scanning  
- **S3 (Simple Storage Service)**: Bucket security and compliance assessment

### Do I need special AWS permissions to run CloudSecVision?

Yes, you need read-only permissions for the services you want to scan. See the [Getting Started](./getting-started) guide for the complete list of required permissions.

## Technical Questions

### Why does the scanner only find SSH issues in EC2?

The current EC2 scanner focuses on the most critical network security issue: SSH exposure to the internet. Future versions will include additional port and protocol checks. You can extend the scanner by modifying `scan/scan_ec2.py`.

### How does the AI analysis work?

CloudSecVision uses Ollama to run large language models locally for security analysis. The AI provides contextual understanding, risk assessment, and detailed remediation recommendations based on your specific findings.

### Can I run CloudSecVision without AI analysis?

Yes, you can run all scanners without AI analysis. Simply omit the `--ai` flag when running scans. The scanners will still generate detailed JSON reports with findings.

### What models does CloudSecVision support for AI analysis?

CloudSecVision works with any Ollama-compatible model, including:
- llama2 (recommended for balanced performance)
- llama2:13b (for more detailed analysis)
- codellama (for technical focus)
- mistral (for faster analysis)

## Setup and Configuration

### How do I configure AWS credentials?

You can configure AWS credentials using any of these methods:
1. AWS CLI: `aws configure`
2. Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
3. IAM roles (for EC2 instances)
4. AWS credential files

### Why can't I connect to Ollama?

Common Ollama connection issues:
1. **Service not running**: Start with `ollama serve`
2. **Model not available**: Pull model with `ollama pull llama2`
3. **Port conflicts**: Ollama defaults to port 11434
4. **Firewall blocking**: Check local firewall settings

### How do I scan multiple AWS regions?

Currently, CloudSecVision scans the default region configured in your AWS credentials. For multi-region scanning, you'll need to run the scanner for each region by changing the `AWS_DEFAULT_REGION` environment variable.

### Can I run CloudSecVision in a Docker container?

While not officially supported yet, you can create a Docker container with Python, AWS CLI, and Ollama. This is planned for future releases.

## Dashboard and Reporting

### The dashboard shows no data. What should I do?

This usually means no scan results are available. Run a scan first:
```bash
python main.py --service all
```
Then restart the dashboard:
```bash
./run_dashboard.sh
```

### Can I export scan results?

Yes, all scan results are saved as JSON files in the `scan/results/` directory. The dashboard also provides export functionality for CSV and JSON formats.

### How often should I run security scans?

Recommended frequency:
- **Daily**: For production environments
- **Weekly**: For development environments  
- **Before deployments**: As part of CI/CD pipelines
- **After changes**: When modifying security configurations

### Can I integrate CloudSecVision with other tools?

Yes, CloudSecVision generates standard JSON reports that can be integrated with:
- SIEM systems (Splunk, ELK Stack)
- Ticketing systems (Jira, ServiceNow)
- Monitoring platforms (CloudWatch, Datadog)
- CI/CD pipelines (GitHub Actions, GitLab CI)

## Security and Privacy

### Does CloudSecVision store my AWS data?

No, CloudSecVision only reads your AWS configuration and generates local reports. No data is transmitted to external services except for AI analysis with your local Ollama instance.

### Is it safe to run CloudSecVision in production?

Yes, CloudSecVision only performs read-only operations on your AWS resources. It cannot modify or delete any AWS resources. However, always test in a development environment first.

### What data does the AI analysis see?

The AI analysis only sees the security findings and configuration data that CloudSecVision collects. When using Ollama locally, this data never leaves your environment.

### Should I be concerned about API rate limits?

CloudSecVision is designed to respect AWS API rate limits. However, in large environments, you might experience throttling. The scanners include built-in retry logic and rate limiting.

## Troubleshooting

### I'm getting permission denied errors

Common causes and solutions:
1. **Insufficient IAM permissions**: Add the required permissions listed in the [Getting Started](./getting-started) guide
2. **Wrong AWS region**: Ensure you're scanning the correct region
3. **Expired credentials**: Refresh your AWS credentials
4. **Cross-account access**: Verify you have access to the resources you're trying to scan

### The scan finds too many false positives

Some findings might be intentional in your environment:
1. **Public S3 buckets**: May be legitimate for static websites
2. **Admin policies**: Some AWS managed policies are intentionally broad
3. **SSH access**: May be required for specific administrative workflows

Review each finding in context of your environment and security requirements.

### Scans are running slowly

Performance optimization tips:
1. **Scan specific services**: Use `--service iam` instead of `--service all`
2. **Check network connectivity**: Slow internet can affect API calls
3. **Region proximity**: Use AWS regions closer to your location
4. **Reduce AI analysis**: Skip `--ai` flag for faster basic scans

### The AI analysis generates unclear responses

Improve AI analysis quality:
1. **Use a larger model**: Try `llama2:13b` instead of `llama2`
2. **Increase context**: Ensure Ollama has sufficient memory allocated
3. **Check model version**: Update to the latest model version
4. **Restart Ollama**: Restart the service to clear any issues

## Best Practices

### How should I prioritize security findings?

Recommended prioritization:
1. **CRITICAL**: Address immediately (public data exposure)
2. **HIGH**: Address within 24-48 hours (SSH exposure, overly permissive policies)
3. **MEDIUM**: Address within 1 week (missing encryption, disabled logging)
4. **LOW**: Address during regular maintenance (missing lifecycle policies)

### What's the best way to remediate findings?

Follow this approach:
1. **Understand the finding**: Use AI analysis for context
2. **Assess business impact**: Consider operational requirements
3. **Test changes**: Implement fixes in development first
4. **Monitor effects**: Watch for any service disruptions
5. **Document changes**: Keep records of security improvements

### How can I prevent similar issues in the future?

Prevention strategies:
1. **Infrastructure as Code**: Use CloudFormation/Terraform with security templates
2. **Automated checks**: Integrate CloudSecVision into CI/CD pipelines
3. **Regular training**: Educate team members on AWS security best practices
4. **Policy enforcement**: Implement AWS Config rules and Service Control Policies

## Getting Help

### Where can I report bugs or request features?

- **GitHub Issues**: [https://github.com/Boualili-Youcef/cloudsecvision/issues](https://github.com/Boualili-Youcef/cloudsecvision/issues)
- **Feature Requests**: Use GitHub issues with the "enhancement" label
- **Security Vulnerabilities**: Report privately via GitHub security advisories

### How can I contribute to CloudSecVision?

See our [Contributing Guide](./contributing) for information on:
- Code contributions
- Documentation improvements
- Bug reports and testing
- Feature suggestions

### Where can I get additional support?

1. **Documentation**: Check this comprehensive documentation first
2. **GitHub Discussions**: Community support and questions
3. **AWS Documentation**: For AWS service-specific information
4. **Ollama Documentation**: For AI model and setup help
