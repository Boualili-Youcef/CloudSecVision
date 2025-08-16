---
sidebar_position: 9
---

# Troubleshooting

Common issues and solutions when using CloudSecVision.

## Installation and Setup Issues

### Python Environment Problems

**Issue: ModuleNotFoundError when running scanners**
```
ModuleNotFoundError: No module named 'boto3'
```

**Solutions:**
1. **Activate virtual environment**:
   ```bash
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   pip list | grep boto3
   python -c "import boto3; print(boto3.__version__)"
   ```

**Issue: Permission denied when creating virtual environment**
```
PermissionError: [Errno 13] Permission denied: '/usr/local/lib/python3.8/site-packages'
```

**Solutions:**
1. **Use --user flag**:
   ```bash
   pip install --user boto3
   ```

2. **Create virtual environment in home directory**:
   ```bash
   cd ~
   python -m venv cloudsecvision-env
   source cloudsecvision-env/bin/activate
   ```

### AWS Configuration Issues

**Issue: NoCredentialsError**
```
botocore.exceptions.NoCredentialsError: Unable to locate credentials
```

**Solutions:**
1. **Configure AWS CLI**:
   ```bash
   aws configure
   # Enter: Access Key ID, Secret Access Key, Region, Output format
   ```

2. **Set environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   ```

3. **Verify credentials**:
   ```bash
   aws sts get-caller-identity
   ```

**Issue: Access Denied errors**
```
ClientError: An error occurred (AccessDenied) when calling the ListPolicies operation
```

**Solutions:**
1. **Check IAM permissions**:
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
           "s3:GetBucket*"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

2. **Test specific permissions**:
   ```bash
   aws iam list-policies --max-items 1
   aws ec2 describe-security-groups --max-items 1
   aws s3api list-buckets
   ```

## Scanner-Specific Issues

### IAM Scanner Problems

**Issue: Empty results despite having policies**
```
✅ IAM report generated at scan/results/iam_scan_report.json (0 issues found)
```

**Troubleshooting:**
1. **Check if policies are attached**:
   ```bash
   aws iam list-entities-for-policy --policy-arn arn:aws:iam::123456789012:policy/YourPolicy
   ```

2. **Verify policy content**:
   ```bash
   aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/YourPolicy
   aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/YourPolicy --version-id v1
   ```

3. **Check for wildcard permissions**:
   ```python
   # Debug IAM scanner
   python -c "
   from scan.scan_iam import scan_iam_permissions, is_policy_too_permissive
   import boto3
   
   iam = boto3.client('iam')
   policies = iam.list_policies(Scope='Local', OnlyAttached=True)['Policies']
   
   for policy in policies:
       policy_arn = policy['Arn']
       version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
       policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
       policy_doc = policy_version['PolicyVersion']['Document']
       
       print(f'Policy: {policy[\"PolicyName\"]}')
       print(f'Too permissive: {is_policy_too_permissive(policy_doc)}')
       print(f'Document: {policy_doc}')
       print('-' * 50)
   "
   ```

### EC2 Scanner Problems

**Issue: No security groups found**
```
✅ EC2 report generated at scan/results/ec2_scan.json (0 issues found)
```

**Troubleshooting:**
1. **Check region**:
   ```bash
   echo $AWS_DEFAULT_REGION
   aws configure get region
   ```

2. **List security groups manually**:
   ```bash
   aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId'
   ```

3. **Check for SSH rules**:
   ```bash
   aws ec2 describe-security-groups \
     --query 'SecurityGroups[?IpPermissions[?FromPort==`22` && IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName}'
   ```

**Issue: Region-specific resources not found**
```
No security groups returned from API
```

**Solutions:**
1. **Scan multiple regions**:
   ```bash
   for region in us-east-1 us-west-2 eu-west-1; do
     echo "Scanning $region..."
     AWS_DEFAULT_REGION=$region python -m scan.scan_ec2
   done
   ```

2. **Check available regions**:
   ```bash
   aws ec2 describe-regions --query 'Regions[].RegionName'
   ```

### S3 Scanner Problems

**Issue: ClientError when accessing buckets**
```
ClientError: An error occurred (AccessDenied) when calling the GetBucketAcl operation
```

**Troubleshooting:**
1. **Check bucket permissions**:
   ```bash
   aws s3api get-bucket-acl --bucket your-bucket-name
   ```

2. **Test bucket access**:
   ```bash
   aws s3api head-bucket --bucket your-bucket-name
   ```

3. **Check bucket region**:
   ```bash
   aws s3api get-bucket-location --bucket your-bucket-name
   ```

**Issue: Timeout errors with large number of buckets**
```
TimeoutError: Request timed out
```

**Solutions:**
1. **Increase timeout in scanner**:
   ```python
   # Modify scan/scan_s3.py
   import boto3
   from botocore.config import Config
   
   config = Config(
       region_name='us-east-1',
       retries={'max_attempts': 3},
       read_timeout=60,
       connect_timeout=60
   )
   
   self.s3 = boto3.client('s3', config=config)
   ```

2. **Run scanner in batches**:
   ```bash
   # Get bucket list
   aws s3api list-buckets --query 'Buckets[:10].Name' --output text > first_10_buckets.txt
   
   # Modify scanner to process specific buckets
   ```

## AI Analysis Issues

### Ollama Connection Problems

**Issue: Connection refused**
```
requests.exceptions.ConnectionError: HTTPConnectionPool(host='localhost', port=11434): Max retries exceeded
```

**Solutions:**
1. **Start Ollama service**:
   ```bash
   ollama serve
   ```

2. **Check if Ollama is running**:
   ```bash
   curl http://localhost:11434/api/tags
   ```

3. **Check port availability**:
   ```bash
   netstat -tlnp | grep 11434
   # or
   lsof -i :11434
   ```

4. **Configure custom Ollama URL**:
   ```python
   # In analysis/ai_analyzer.py
   OLLAMA_URL = "http://localhost:11434"  # Default
   # or for remote Ollama
   OLLAMA_URL = "http://your-ollama-server:11434"
   ```

**Issue: Model not found**
```
Error: model 'llama2' not found
```

**Solutions:**
1. **List available models**:
   ```bash
   ollama list
   ```

2. **Pull required model**:
   ```bash
   ollama pull llama2
   # or for specific version
   ollama pull llama2:13b
   ```

3. **Check model status**:
   ```bash
   ollama show llama2
   ```

### AI Response Quality Issues

**Issue: AI generates poor quality analysis**

**Solutions:**
1. **Use a larger model**:
   ```bash
   ollama pull llama2:13b
   # Modify AI_CONFIG in analysis/ai_analyzer.py
   AI_CONFIG['model_name'] = 'llama2:13b'
   ```

2. **Adjust temperature setting**:
   ```python
   # Lower temperature for more consistent responses
   AI_CONFIG['temperature'] = 0.1  # Instead of 0.3
   ```

3. **Improve prompt context**:
   ```python
   # Add more context to prompts
   prompt = f"""
   You are analyzing AWS security findings for a production environment.
   
   Company context: {company_context}
   Compliance requirements: {compliance_requirements}
   
   Findings: {findings}
   """
   ```

**Issue: AI analysis takes too long**

**Solutions:**
1. **Use faster model**:
   ```bash
   ollama pull mistral
   ```

2. **Reduce analysis scope**:
   ```python
   # Process findings in smaller batches
   def batch_analyze(findings, batch_size=5):
       for i in range(0, len(findings), batch_size):
           batch = findings[i:i + batch_size]
           analyze_batch(batch)
   ```

3. **Set timeout limits**:
   ```python
   # In AI analyzer
   response = requests.post(
       f"{OLLAMA_URL}/api/generate",
       json=payload,
       timeout=30  # 30 second timeout
   )
   ```

## Dashboard Issues

### Streamlit Problems

**Issue: Dashboard won't start**
```
ModuleNotFoundError: No module named 'streamlit'
```

**Solutions:**
1. **Install Streamlit**:
   ```bash
   pip install streamlit
   # or
   pip install -r requirements.txt
   ```

2. **Check Streamlit installation**:
   ```bash
   streamlit --version
   ```

**Issue: Port already in use**
```
OSError: [Errno 98] Address already in use
```

**Solutions:**
1. **Use different port**:
   ```bash
   streamlit run dashboard.py --server.port 8502
   ```

2. **Kill existing process**:
   ```bash
   lsof -ti:8501 | xargs kill -9
   # or
   pkill -f streamlit
   ```

3. **Find what's using the port**:
   ```bash
   lsof -i :8501
   netstat -tlnp | grep 8501
   ```

### Dashboard Display Issues

**Issue: No data displayed in dashboard**
```
No scan results found. Please run a scan first.
```

**Solutions:**
1. **Run scanners to generate data**:
   ```bash
   python main.py --service all
   ```

2. **Check results directory**:
   ```bash
   ls -la scan/results/
   cat scan/results/iam_scan_report.json
   ```

3. **Verify file paths in dashboard**:
   ```python
   # Debug data loading
   python -c "
   from dashboard import load_scan_results
   results = load_scan_results()
   print('Results loaded:', results)
   "
   ```

**Issue: Charts not displaying**
```
Plotly charts appear blank or don't render
```

**Solutions:**
1. **Update Plotly**:
   ```bash
   pip install --upgrade plotly
   ```

2. **Check browser compatibility**:
   - Use modern browser (Chrome, Firefox, Safari)
   - Disable ad blockers that might block JavaScript

3. **Clear browser cache**:
   - Hard refresh (Ctrl+F5 or Cmd+Shift+R)
   - Clear browser cache and cookies

## Performance Issues

### Slow Scan Performance

**Issue: Scans taking too long**

**Optimization strategies:**
1. **Scan specific services**:
   ```bash
   python main.py --service iam  # Fastest
   python main.py --service ec2  # Medium
   python main.py --service s3   # Slowest (comprehensive)
   ```

2. **Skip AI analysis for quick scans**:
   ```bash
   python main.py --service all  # Without --ai flag
   ```

3. **Optimize AWS API calls**:
   ```python
   # Use pagination for large result sets
   def get_all_policies():
       paginator = iam.get_paginator('list_policies')
       for page in paginator.paginate(Scope='Local', OnlyAttached=True):
           for policy in page['Policies']:
               yield policy
   ```

### Memory Issues

**Issue: High memory usage during scans**

**Solutions:**
1. **Process results in batches**:
   ```python
   def process_large_dataset(items, batch_size=100):
       for i in range(0, len(items), batch_size):
           batch = items[i:i + batch_size]
           process_batch(batch)
           # Clear batch from memory
           del batch
   ```

2. **Use generators instead of lists**:
   ```python
   def scan_buckets():
       """Generator that yields results instead of storing all in memory"""
       for bucket in self.list_buckets():
           yield self.scan_bucket(bucket)
   ```

## Network and Connectivity Issues

### AWS API Connectivity

**Issue: SSL/TLS certificate errors**
```
SSLError: HTTPSConnectionPool(host='iam.amazonaws.com', port=443)
```

**Solutions:**
1. **Update certificates**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update && sudo apt-get install ca-certificates
   
   # CentOS/RHEL  
   sudo yum update ca-certificates
   
   # macOS
   brew upgrade ca-certificates
   ```

2. **Check system time**:
   ```bash
   date
   # Ensure system time is accurate
   ```

**Issue: Rate limiting**
```
ClientError: An error occurred (Throttling) when calling the operation: Request rate exceeded
```

**Solutions:**
1. **Implement exponential backoff**:
   ```python
   import time
   import random
   
   def retry_with_backoff(func, max_retries=3):
       for attempt in range(max_retries):
           try:
               return func()
           except ClientError as e:
               if 'Throttling' in str(e):
                   wait_time = (2 ** attempt) + random.uniform(0, 1)
                   time.sleep(wait_time)
                   continue
               raise
       raise Exception("Max retries exceeded")
   ```

2. **Reduce concurrent requests**:
   ```python
   # Add delays between API calls
   time.sleep(0.1)  # 100ms delay
   ```

## Environment-Specific Issues

### Windows-Specific Problems

**Issue: Path separator issues**
```
FileNotFoundError: [Errno 2] No such file or directory: 'scan\\results\\file.json'
```

**Solutions:**
1. **Use os.path.join()**:
   ```python
   import os
   output_path = os.path.join("scan", "results", "iam_scan_report.json")
   ```

2. **Use pathlib**:
   ```python
   from pathlib import Path
   output_path = Path("scan") / "results" / "iam_scan_report.json"
   ```

### Docker-Specific Issues

**Issue: Running CloudSecVision in containers**

**Solutions:**
1. **Create Dockerfile**:
   ```dockerfile
   FROM python:3.8-slim
   
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install -r requirements.txt
   
   COPY . .
   
   # Set AWS credentials as environment variables
   ENV AWS_ACCESS_KEY_ID=""
   ENV AWS_SECRET_ACCESS_KEY=""
   ENV AWS_DEFAULT_REGION="us-east-1"
   
   CMD ["python", "main.py", "--service", "all"]
   ```

2. **Docker Compose with Ollama**:
   ```yaml
   version: '3.8'
   services:
     cloudsecvision:
       build: .
       environment:
         - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
         - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
       depends_on:
         - ollama
     
     ollama:
       image: ollama/ollama
       ports:
         - "11434:11434"
       volumes:
         - ollama_data:/root/.ollama
   
   volumes:
     ollama_data:
   ```

## Debug Mode and Logging

### Enable Debug Logging

Add debug information to troubleshoot issues:

```python
import logging

# Enable debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add to scanners
logger = logging.getLogger(__name__)
logger.debug(f"Processing bucket: {bucket_name}")
logger.debug(f"API response: {response}")
```

### Verbose Output

Run scanners with verbose output:

```bash
# Add verbose flag to main.py
python main.py --service all --verbose

# Or debug specific components
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)

from scan.scan_iam import scan_iam_permissions
results = scan_iam_permissions()
print(f'Debug: Found {len(results)} issues')
"
```

### Health Check Script

Create a health check script to diagnose common issues:

```bash
#!/bin/bash
# health_check.sh

echo "CloudSecVision Health Check"
echo "=========================="

# Python version
echo "Python version:"
python --version

# Dependencies
echo -e "\nChecking dependencies..."
python -c "import boto3; print(f'boto3: {boto3.__version__}')" 2>/dev/null || echo "❌ boto3 not installed"
python -c "import streamlit; print(f'streamlit: {streamlit.__version__}')" 2>/dev/null || echo "❌ streamlit not installed"

# AWS credentials  
echo -e "\nAWS credentials:"
aws sts get-caller-identity 2>/dev/null && echo "✅ AWS credentials OK" || echo "❌ AWS credentials not configured"

# Ollama service
echo -e "\nOllama service:"
curl -s http://localhost:11434/api/tags >/dev/null && echo "✅ Ollama running" || echo "❌ Ollama not accessible"

# File permissions
echo -e "\nFile permissions:"
[ -w scan/results/ ] && echo "✅ Results directory writable" || echo "❌ Results directory not writable"

echo -e "\nHealth check complete!"
```

If you continue to experience issues not covered here, please:

1. Check the [FAQ](./faq) for additional common questions
2. Search existing [GitHub issues](https://github.com/Boualili-Youcef/cloudsecvision/issues)
3. Create a new issue with detailed error information and environment details
