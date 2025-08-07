# 📊 CloudSecVision Dashboard

Interactive Streamlit dashboard to visualize and analyze AWS security scan results.

## 🚀 Quick Start

```bash
# Option 1: Launch script
./run_dashboard.sh

# Option 2: Direct command
streamlit run dashboard.py --server.port 8501
```

Dashboard will be accessible at: **http://localhost:8501**

## 🎯 Features

### 🏠 Overview
- **Global metrics**: Total issues count per service
- **Interactive charts**: Vulnerability distribution
- **Risk level**: Automatic security level assessment
- **Visual alerts**: Color-coded by criticality

### 🖥️ EC2 Analysis  
- Detailed list of vulnerable Security Groups
- Exposed ports and problematic rules
- Charts of most at-risk SGs
- Correction recommendations

### 👤 IAM Analysis
- Detected overly permissive policies
- Details of problematic permissions
- ARNs and names of concerned policies
- Correction suggestions

### 🪣 S3 Analysis
- Identified public buckets
- Detailed exposure level
- AWS CLI commands for correction
- Critical alerts for sensitive data

### 💡 Recommendations
- AWS security best practices
- Recommended immediate actions
- Links to official documentation
- Step-by-step remediation guide

## 🎨 Interface

### Navigation
- **Sidebar**: Main navigation between sections
- **Actions**: Buttons to launch new scans
- **Refresh**: Real-time data updates

### Visualizations
- **Plotly charts**: Interactive and responsive
- **Pandas tables**: Detailed and filterable data
- **Metrics**: Real-time KPIs
- **Alerts**: Color-coded by criticality

### Responsive Design
- **Adaptive layout**: Optimized for desktop and mobile
- **Custom theme**: CloudSecVision colors
- **Modern CSS**: Professional interface

## 🔧 Configuration

### Streamlit Settings
File `.streamlit/config.toml`:
```toml
[theme]
primaryColor = "#667eea"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"

[server]
port = 8501
headless = true
```

### Dependencies
```bash
pip install streamlit plotly pandas boto3
```

## 📱 Usage

### 1. Initial launch
```bash
cd cloudsecvision
./run_dashboard.sh
```

### 2. Navigation
- **Overview**: General security status
- **Services**: Details per AWS service (EC2, IAM, S3)
- **Recommendations**: Remediation guide

### 3. Available actions
- **🔄 New scan**: Launches all security scans
- **📊 Refresh**: Reloads existing data
- **📥 Export**: Report backup (future feature)

### 4. Interactivity
- **Charts**: Zoom, filtering, hover
- **Tables**: Sort, search, pagination
- **Expanders**: Details on demand

## 🔍 Displayed Data

### Data sources
- `scan/results/ec2_scan.json`: EC2 results
- `scan/results/iam_scan_report.json`: IAM results  
- `scan/results/s3_scan_report.json`: S3 results

### Data structure
```json
{
  "ec2": [
    {
      "GroupId": "sg-xxx",
      "GroupName": "test-sg", 
      "Port": 22,
      "IpRange": "0.0.0.0/0",
      "Issue": "SSH port 22 open to the world"
    }
  ],
  "iam": [...],
  "s3": [...]
}
```

## 🚨 Alerts and Notifications

### Criticality levels
- **🚨 CRITICAL**: Immediate action required
- **⚠️ MODERATE**: Correction recommended
- **✅ SECURE**: No issues detected

### Alert types
- **Public S3 buckets**: Red alert, immediate action
- **Open SSH ports**: Orange alert, quick fix
- **IAM policies**: Yellow alert, review needed

## 🔄 Data Updates

### Automatic
- **Refresh button**: Reloads from JSON files
- **Auto-refresh**: Every 5 minutes (optional)

### Manual
- **New scan**: Executes all scan scripts
- **Import file**: Load external results

## 🌐 Network Access

### Local
- **http://localhost:8501**: Local access only

### Network
- **http://[IP]:8501**: Access from local network
- **SSH tunnel**: For secure remote access

## 📊 Metrics and KPIs

### Main metrics
- **Total Issues**: Sum of all vulnerabilities
- **Per service**: EC2, IAM, S3 separately
- **Risk level**: Automatically calculated score
- **Trends**: Evolution over time

### Charts
- **Donut chart**: Distribution by service
- **Bar chart**: Top vulnerable resources
- **Timeline**: Historical evolution (future feature)

## 🛡️ Dashboard Security

### Best practices
- **Local access**: Default on localhost only
- **No authentication**: Intended for internal use
- **Sensitive data**: No permanent storage
- **HTTPS**: Recommended for production

### Limitations
- **No auth**: All users have full access
- **No logs**: User actions not tracked
- **No cache**: Full reload each time

## 🔮 Future Improvements

### Planned features
- **🔐 Authentication**: Login/logout
- **📈 History**: Trend tracking
- **📧 Notifications**: Email/Slack alerts
- **🤖 AI**: Automatic analysis with Ollama
- **📤 Export**: PDF, Excel, CSV
- **⚙️ Settings**: Customizable configuration

### Integrations
- **AWS Organizations**: Multi-account
- **CloudWatch**: Real-time metrics
- **Lambda**: Automated scans
- **SNS**: Push notifications

---

**🛡️ CloudSecVision Dashboard - Developed by Youcef**  
*M1 Cloud Security & AWS Project*
