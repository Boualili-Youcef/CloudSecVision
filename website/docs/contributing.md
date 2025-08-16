---
sidebar_position: 11
---

# Contributing

Welcome to CloudSecVision! We're excited that you're interested in contributing to this open-source AWS security project. This guide will help you get started with contributing code, documentation, and ideas.

## Ways to Contribute

### 🐛 Bug Reports
- Report bugs and issues you encounter
- Provide detailed reproduction steps
- Include environment information and logs

### 💡 Feature Requests
- Suggest new scanners for additional AWS services
- Propose dashboard enhancements
- Request AI analysis improvements

### 🛠️ Code Contributions
- Fix bugs and implement features
- Improve scanner accuracy and performance
- Add new security checks and detections

### 📚 Documentation
- Improve existing documentation
- Add examples and use cases
- Translate content to other languages

### 🧪 Testing
- Test new features and releases
- Contribute test cases and scenarios
- Report compatibility issues

## Getting Started

### Development Environment Setup

1. **Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/cloudsecvision.git
   cd cloudsecvision
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

3. **Configure Pre-commit Hooks**
   ```bash
   # Install pre-commit hooks for code quality
   pre-commit install
   ```

4. **Verify Installation**
   ```bash
   # Run tests to ensure everything works
   python -m pytest tests/
   
   # Run a quick scan test
   python -m scan.scan_iam
   ```

### Development Workflow

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```

2. **Make Your Changes**
   - Follow the coding standards (see below)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run unit tests
   python -m pytest tests/
   
   # Run integration tests
   python -m pytest tests/integration/
   
   # Test specific scanner
   python -m scan.scan_iam
   python -m scan.scan_ec2
   python -m scan.scan_s3
   
   # Test dashboard
   streamlit run dashboard.py
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add new S3 lifecycle policy check"
   # Use conventional commit format (see below)
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   # Then create a pull request on GitHub
   ```

## Coding Standards

### Python Code Style

We follow PEP 8 with some project-specific conventions:

```python
# Good example
class S3SecurityScanner:
    """Scanner for S3 bucket security configurations."""
    
    def __init__(self):
        """Initialize the S3 scanner with boto3 client."""
        self.s3 = boto3.client('s3')
        self.results = []
    
    def check_bucket_encryption(self, bucket_name: str) -> dict:
        """
        Check if bucket has server-side encryption enabled.
        
        Args:
            bucket_name: Name of the S3 bucket to check
            
        Returns:
            Dictionary with encryption status and details
            
        Raises:
            ClientError: If unable to access bucket configuration
        """
        try:
            response = self.s3.get_bucket_encryption(Bucket=bucket_name)
            return {
                'status': 'enabled',
                'algorithm': response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return {'status': 'disabled', 'algorithm': None}
            raise
```

### Code Quality Tools

We use several tools to maintain code quality:

```bash
# Format code with black
black scan/ analysis/ dashboard.py

# Sort imports with isort  
isort scan/ analysis/ dashboard.py

# Lint code with flake8
flake8 scan/ analysis/ dashboard.py

# Type checking with mypy
mypy scan/ analysis/ dashboard.py

# Security scanning with bandit
bandit -r scan/ analysis/ dashboard.py
```

### Commit Message Format

We use [Conventional Commits](https://conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Build process or auxiliary tool changes

**Examples:**
```bash
git commit -m "feat(s3): add lifecycle policy security check"
git commit -m "fix(dashboard): resolve data loading issue"
git commit -m "docs: update getting started guide"
git commit -m "test(iam): add unit tests for policy analyzer"
```

## Contributing to Scanners

### Adding New Security Checks

To add a new security check to an existing scanner:

1. **Identify the Security Risk**
   ```python
   # Example: Check for S3 bucket notification configuration
   def check_bucket_notifications(self, bucket_name: str) -> dict:
       """Check if bucket has event notifications configured for security monitoring."""
       try:
           response = self.s3.get_bucket_notification_configuration(Bucket=bucket_name)
           configurations = response.get('Configurations', [])
           
           if not configurations:
               return {
                   'issue': 'No event notifications configured',
                   'severity': 'MEDIUM',
                   'recommendation': 'Configure CloudTrail or CloudWatch Events for bucket monitoring'
               }
           
           return {'status': 'configured', 'count': len(configurations)}
           
       except ClientError as e:
           if e.response['Error']['Code'] == 'NotificationConfigurationNotFoundError':
               return {
                   'issue': 'No notification configuration found',
                   'severity': 'MEDIUM',
                   'recommendation': 'Enable S3 event notifications for security monitoring'
               }
           raise
   ```

2. **Add to Scanner Main Function**
   ```python
   def scan_bucket_comprehensive(self, bucket_name):
       """Comprehensive security scan of an S3 bucket."""
       bucket_issues = []
       
       # Existing checks...
       bucket_issues.extend(self.check_bucket_public_access(bucket_name))
       bucket_issues.extend(self.check_bucket_encryption(bucket_name))
       
       # New check
       notification_result = self.check_bucket_notifications(bucket_name)
       if 'issue' in notification_result:
           bucket_issues.append(notification_result)
       
       return bucket_issues
   ```

3. **Add Tests**
   ```python
   # tests/test_s3_scanner.py
   def test_check_bucket_notifications():
       """Test S3 bucket notification configuration check."""
       scanner = S3SecurityScanner()
       
       # Mock S3 client response
       with patch.object(scanner.s3, 'get_bucket_notification_configuration') as mock_get:
           mock_get.return_value = {'Configurations': []}
           
           result = scanner.check_bucket_notifications('test-bucket')
           
           assert 'issue' in result
           assert result['severity'] == 'MEDIUM'
           assert 'notification' in result['issue'].lower()
   ```

### Creating a New Scanner

To create a scanner for a new AWS service:

1. **Create Scanner File**
   ```python
   # scan/scan_rds.py
   import boto3
   import json
   import os
   from botocore.exceptions import ClientError
   
   class RDSSecurityScanner:
       """Scanner for RDS database security configurations."""
       
       def __init__(self):
           self.rds = boto3.client('rds')
           self.results = []
       
       def scan_database_instances(self):
           """Scan all RDS instances for security issues."""
           try:
               response = self.rds.describe_db_instances()
               instances = response['DBInstances']
               
               for instance in instances:
                   instance_issues = self.analyze_instance_security(instance)
                   self.results.extend(instance_issues)
               
               return self.results
               
           except Exception as e:
               print(f"Error scanning RDS instances: {e}")
               return []
       
       def analyze_instance_security(self, instance):
           """Analyze security configuration of an RDS instance."""
           issues = []
           
           # Check for public accessibility
           if instance.get('PubliclyAccessible', False):
               issues.append({
                   'InstanceId': instance['DBInstanceIdentifier'],
                   'Issue': 'Database instance is publicly accessible',
                   'Severity': 'CRITICAL',
                   'Recommendation': 'Set PubliclyAccessible to false'
               })
           
           # Check for encryption
           if not instance.get('StorageEncrypted', False):
               issues.append({
                   'InstanceId': instance['DBInstanceIdentifier'],
                   'Issue': 'Database storage is not encrypted',
                   'Severity': 'HIGH',
                   'Recommendation': 'Enable storage encryption'
               })
           
           return issues
   
   def main():
       """Main function for RDS security scanning."""
       print("🛡️ CloudSecVision - RDS Security Scanner")
       print("=" * 50)
       
       scanner = RDSSecurityScanner()
       results = scanner.scan_database_instances()
       
       # Save results
       script_dir = os.path.dirname(os.path.abspath(__file__))
       results_dir = os.path.join(script_dir, "results")
       os.makedirs(results_dir, exist_ok=True)
       
       output_path = os.path.join(results_dir, "rds_scan_report.json")
       
       with open(output_path, "w") as f:
           json.dump(results, f, indent=2)
       
       print(f"✅ RDS report generated at {output_path} ({len(results)} issues found)")
       return results
   
   if __name__ == "__main__":
       main()
   ```

2. **Add to Main Script**
   ```python
   # main.py - add RDS support
   parser.add_argument('--service', choices=['ec2', 'iam', 's3', 'rds', 'all'], default='all')
   
   if args.service in ['rds', 'all']:
       print("🔍 Scanning RDS Databases...")
       from scan.scan_rds import main as scan_rds
       results['rds'] = scan_rds()
       print()
   ```

3. **Add Dashboard Support**
   ```python
   # dashboard.py - add RDS page
   def display_rds_page():
       st.header("🗄️ RDS Database Security Analysis")
       
       if st.button("🔍 Run RDS Scan"):
           with st.spinner("Scanning RDS databases..."):
               from scan.scan_rds import main as scan_rds
               results = scan_rds()
               st.session_state['rds_results'] = results
           st.success(f"RDS scan completed! Found {len(results)} issues.")
       
       # Display results...
   ```

## Contributing to Documentation

### Documentation Structure

Our documentation is built with Docusaurus and follows this structure:

```
website/docs/
├── intro.md                    # Main introduction
├── getting-started.md          # Setup guide
├── scanners/                   # Scanner documentation
│   ├── overview.md
│   ├── iam-scanner.md
│   ├── ec2-scanner.md
│   └── s3-scanner.md
├── dashboard/                  # Dashboard documentation
│   └── overview.md
├── ai-analysis/               # AI analysis documentation
│   └── overview.md
├── faq.md                     # Frequently asked questions
├── troubleshooting.md         # Common issues and solutions
├── best-practices.md          # Security best practices
└── contributing.md            # This file
```

### Writing Documentation

**Style Guidelines:**
- Use clear, concise language
- Include code examples for technical concepts
- Add screenshots for UI elements
- Use consistent formatting and structure

**Example Documentation:**
```markdown
---
sidebar_position: 3
---

# Feature Name

Brief description of the feature and its purpose.

## Overview

Detailed explanation of what the feature does and why it's useful.

## Usage

### Basic Usage

```bash
# Simple command example
python -m scan.new_scanner
```

### Advanced Configuration

```python
# Code example with explanation
scanner = NewScanner(
    region='us-east-1',
    enable_detailed_analysis=True
)
results = scanner.scan()
```

## Examples

### Real-world Example

Detailed walkthrough of a common use case.

## Troubleshooting

Common issues and their solutions.

## Next Steps

Links to related documentation.
```

### Building Documentation Locally

```bash
# Navigate to website directory
cd website

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

## Contributing to AI Analysis

### Improving AI Prompts

AI analysis quality depends heavily on prompt engineering:

```python
# Good prompt structure
def create_security_analysis_prompt(findings, context=""):
    """Create effective prompt for security analysis."""
    prompt = f"""
You are a senior AWS security architect with 10+ years of experience.
You are analyzing security findings for a {context} environment.

Your task:
1. Assess the overall security posture
2. Identify the most critical risks
3. Provide specific, actionable recommendations
4. Consider business impact and compliance requirements

Security Findings:
{json.dumps(findings, indent=2)}

Please structure your response as:
- Executive Summary (2-3 sentences)
- Risk Level (CRITICAL/HIGH/MEDIUM/LOW) with justification
- Top 3 Priority Actions with specific steps
- Long-term Security Recommendations
- Compliance Considerations

Focus on practical, implementable solutions.
"""
    return prompt
```

### Adding New AI Features

1. **Implement the Feature**
   ```python
   # analysis/ai_analyzer.py
   def generate_compliance_report(findings, framework='SOC2'):
       """Generate compliance-specific analysis."""
       compliance_mappings = {
           'SOC2': {
               'CC6.1': 'Logical access security measures',
               'CC6.2': 'Authentication and access controls'
           }
       }
       
       prompt = f"""
       Analyze these security findings for {framework} compliance:
       {json.dumps(findings, indent=2)}
       
       Map findings to specific {framework} controls and provide:
       1. Compliance status for each relevant control
       2. Gaps that need to be addressed
       3. Evidence requirements for auditors
       4. Remediation priority based on compliance risk
       """
       
       return generate_ai_response(prompt)
   ```

2. **Add Tests**
   ```python
   # tests/test_ai_analyzer.py
   def test_compliance_report_generation():
       findings = [{'service': 'iam', 'issue': 'overly permissive policy'}]
       report = generate_compliance_report(findings, 'SOC2')
       assert 'CC6.1' in report or 'CC6.2' in report
   ```

## Testing Guidelines

### Writing Tests

We use pytest for testing. Write comprehensive tests for new features:

```python
# tests/test_s3_scanner.py
import pytest
from unittest.mock import patch, MagicMock
from scan.scan_s3 import S3SecurityScanner

class TestS3SecurityScanner:
    """Test cases for S3 security scanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = S3SecurityScanner()
    
    @patch('boto3.client')
    def test_list_buckets_success(self, mock_boto_client):
        """Test successful bucket listing."""
        # Mock S3 client
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-bucket-1'},
                {'Name': 'test-bucket-2'}
            ]
        }
        
        # Create new scanner instance
        scanner = S3SecurityScanner()
        buckets = scanner.list_buckets()
        
        assert len(buckets) == 2
        assert 'test-bucket-1' in buckets
        assert 'test-bucket-2' in buckets
    
    @patch('boto3.client')
    def test_check_bucket_encryption_enabled(self, mock_boto_client):
        """Test bucket with encryption enabled."""
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        mock_s3.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        }
        
        scanner = S3SecurityScanner()
        result = scanner.check_bucket_encryption('test-bucket')
        
        assert result['status'] == 'enabled'
        assert result['algorithm'] == 'AES256'
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_s3_scanner.py

# Run with coverage
python -m pytest --cov=scan --cov=analysis

# Run integration tests (requires AWS credentials)
python -m pytest tests/integration/
```

## Pull Request Process

### Before Submitting

1. **Ensure all tests pass**
   ```bash
   python -m pytest tests/
   ```

2. **Check code quality**
   ```bash
   black scan/ analysis/ dashboard.py
   flake8 scan/ analysis/ dashboard.py
   mypy scan/ analysis/ dashboard.py
   ```

3. **Update documentation**
   - Add docstrings to new functions
   - Update relevant documentation files
   - Add examples if needed

4. **Test manually**
   - Run the affected scanners
   - Test dashboard functionality
   - Verify AI analysis works

### Pull Request Template

When creating a pull request, use this template:

```markdown
## Description
Brief description of the changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Changes Made
- [ ] Added new security check for [service]
- [ ] Fixed issue with [component]
- [ ] Improved [specific functionality]
- [ ] Updated documentation for [topic]

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)
Include screenshots for UI changes.

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] Documentation updated
- [ ] No new warnings introduced
```

## Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please:

- **Be respectful**: Treat all community members with respect
- **Be collaborative**: Work together constructively
- **Be inclusive**: Welcome newcomers and help them get started
- **Be professional**: Keep discussions focused and productive

### Getting Help

If you need help contributing:

1. **Check existing documentation** first
2. **Search existing issues** on GitHub
3. **Ask questions** in GitHub Discussions
4. **Join community discussions** about new features

### Recognition

Contributors are recognized in several ways:

- **GitHub contributors list**: Automatic recognition for code contributions
- **Documentation credits**: Attribution in documentation you help improve
- **Feature announcements**: Credit in release notes for significant contributions
- **Community showcase**: Highlighting exceptional contributions

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

Before releasing a new version:

1. **Update version numbers** in relevant files
2. **Update CHANGELOG.md** with new features and fixes
3. **Run full test suite** including integration tests
4. **Update documentation** for new features
5. **Create release notes** highlighting key changes

Thank you for contributing to CloudSecVision! Your contributions help make AWS environments more secure for everyone.
