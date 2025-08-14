```markdown
# CloudSecVision - Developer Guide

## 🛠️ Development Environment Setup

### Prerequisites

- Python 3.8+ installed
- Git installed
- AWS account and credentials for testing
- Code editor (VS Code recommended)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/Boualili-Youcef/cloudsecvision.git
cd cloudsecvision

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black isort flake8
```

## 📂 Project Structure

```
cloudsecvision/
├── analysis/               # Analysis tools and AI integration
│   ├── __init__.py
│   └── ai_analyzer.py      # AI-powered analysis using Ollama
├── aws/                    # AWS-specific utilities
├── config/                 # Configuration files
├── data/                   # Sample data and templates
├── docs/                   # Documentation
├── scan/                   # Security scanning modules
│   ├── __init__.py
│   ├── scan_ec2.py         # EC2 security group scanner
│   ├── scan_iam.py         # IAM policy scanner
│   ├── scan_s3.py          # S3 bucket scanner
│   └── results/            # Scan result output directory
├── test/                   # Test cases
├── dashboard.py            # Streamlit dashboard
├── main.py                 # Command-line interface
├── requirements.txt        # Project dependencies
└── run_dashboard.sh        # Dashboard launch script
```

## 🧩 Core Components

### Scanner Modules

All scanners follow a similar pattern:

1. Connect to AWS using boto3
2. Retrieve resources to analyze
3. Check for security issues against predefined criteria
4. Generate structured findings
5. Save results as JSON

Example skeleton for a new scanner:

```python
import boto3
import json
import os

def scan_my_service():
    """Scan AWS MyService for security issues"""
    client = boto3.client('myservice')
    results = []
    
    # 1. Retrieve resources
    resources = client.list_resources()
    
    # 2. Analyze each resource
    for resource in resources.get('Resources', []):
        # 3. Check for issues
        if has_security_issue(resource):
            # 4. Add findings
            results.append({
                'ResourceId': resource['Id'],
                'Issue': 'Description of the issue',
                'Severity': 'HIGH',
                'Recommendation': 'How to fix it'
            })
    
    # 5. Save results
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    
    output_path = os.path.join(results_dir, "myservice_scan_report.json")
    
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"✅ MyService report generated at {output_path} ({len(results)} issues found)")
    
    return results
```

### AI Analyzer

The AI analyzer uses Ollama to process security findings:

1. Prepare a prompt with findings data
2. Send the prompt to Ollama API
3. Parse and format the response
4. Return structured analysis results

To extend:

```python
def generate_myservice_report(myservice_results):
    """Generate a comprehensive MyService security report using Ollama AI"""
    
    print("🤖 Generating MyService security report with AI...")
    
    if not myservice_results or len(myservice_results) == 0:
        return "No MyService security issues found. Your configuration appears to be secure."

    # Construct the prompt
    prompt = f"""
    I need you to analyze these AWS MyService security findings and provide:
    1. A clear explanation of each security issue
    2. The potential risks they pose
    3. Recommended steps for remediation
    4. Overall security assessment

    Here are the scan results:
    {json.dumps(myservice_results, indent=2)}

    Format your response with markdown headings and bullet points.
    """

    # Call Ollama API
    try:
        response = requests.post("http://localhost:11434/api/generate",
                                headers={"Content-Type": "application/json"},
                                json={"model": "llama3.2:3b", "prompt": prompt, "stream": False})
        
        if response.status_code == 200:
            analysis = response.json().get("response", "")
            return analysis
        else:
            return get_fallback_analysis(len(myservice_results))
    
    except Exception as e:
        print(f"Error generating AI report: {e}")
        return get_fallback_analysis(len(myservice_results))
```

### Dashboard

The dashboard uses Streamlit components:

1. Define page layout and navigation
2. Create UI elements for user interaction
3. Run scanners based on user input
4. Display and visualize results

To add a new service page:

```python
def display_myservice_page():
    """Display MyService security analysis page"""
    st.title("🔍 MyService Security Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🚀 Run MyService Scan"):
            with st.spinner("Scanning MyService configurations..."):
                results = scan_myservice()
                st.session_state.myservice_results = results
                st.success(f"Scan complete! Found {len(results)} issues.")
    
    with col2:
        if st.button("🤖 Generate AI Report", disabled="myservice_results" not in st.session_state):
            with st.spinner("Generating AI analysis..."):
                analysis = generate_myservice_report(st.session_state.myservice_results)
                st.session_state.myservice_analysis = analysis
                st.success("AI analysis complete!")
    
    # Display results if available
    if "myservice_results" in st.session_state:
        display_myservice_findings(st.session_state.myservice_results)
    
    # Display AI analysis if available
    if "myservice_analysis" in st.session_state:
        display_myservice_report(st.session_state.myservice_analysis)
```

## 🧪 Testing

Add tests for new functionality:

```python
# test/test_myservice_scanner.py

import unittest
from unittest.mock import patch, MagicMock
from scan.scan_myservice import scan_myservice

class TestMyServiceScanner(unittest.TestCase):
    @patch('boto3.client')
    def test_scan_myservice(self, mock_boto3_client):
        # Setup mock response
        mock_client = MagicMock()
        mock_client.list_resources.return_value = {
            'Resources': [
                {'Id': 'resource-1', 'Configuration': {'setting': 'insecure'}},
                {'Id': 'resource-2', 'Configuration': {'setting': 'secure'}}
            ]
        }
        mock_boto3_client.return_value = mock_client
        
        # Call function under test
        results = scan_myservice()
        
        # Assertions
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['ResourceId'], 'resource-1')

if __name__ == '__main__':
    unittest.main()
```

Run tests with:

```bash
pytest test/
```

## 📋 Coding Standards

- Use PEP 8 style guidelines
- Add docstrings to all functions
- Use type hints where appropriate
- Keep functions focused on a single responsibility
- Use meaningful variable names

Format code with:

```bash
# Format code
black .

# Sort imports
isort .

# Check for issues
flake8
```

## 🔄 Git Workflow

1. Create a feature branch
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. Make changes and commit
   ```bash
   git add .
   git commit -m "Add comprehensive feature description"
   ```

3. Push and create pull request
   ```bash
   git push origin feature/my-new-feature
   ```

## 📦 Deployment

Package the application for distribution:

```bash
pip install setuptools wheel
python setup.py sdist bdist_wheel
```

## 🚀 Contributing

1. Ensure all tests pass
2. Update documentation for any new features
3. Add appropriate error handling
4. Follow the established patterns for consistency
```
