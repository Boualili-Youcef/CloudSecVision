import streamlit as st
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import boto3
from scan.scan_ec2 import scan_ec2_security_groups
from scan.scan_iam import scan_iam_permissions
from scan.scan_s3 import main as scan_s3
from analysis.ai_analyzer import analyze_security_issues, generate_iam_report

# Page configuration
st.set_page_config(
    page_title="🛡️ CloudSecVision Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin-bottom: 1rem;
    }
    .critical-alert {
        background: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .success-alert {
        background: #e8f5e8;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .warning-alert {
        background: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .info-alert {
        background: #e3f2fd;
        border-left: 4px solid #2196f3;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)

def load_scan_results():
    """Load existing scan results from JSON files"""
    results = {}
    results_dir = "scan/results"
    
    # Load S3 results
    s3_file = os.path.join(results_dir, "s3_scan_report.json")
    if os.path.exists(s3_file):
        with open(s3_file, 'r') as f:
            results['s3'] = json.load(f)
    
    # Load IAM results
    iam_file = os.path.join(results_dir, "iam_scan_report.json")
    if os.path.exists(iam_file):
        with open(iam_file, 'r') as f:
            results['iam'] = json.load(f)
    
    # Load EC2 results
    ec2_file = os.path.join(results_dir, "ec2_scan.json")
    if os.path.exists(ec2_file):
        with open(ec2_file, 'r') as f:
            results['ec2'] = json.load(f)
    
    return results

def run_scans():
    """Execute security scans for all services"""
    st.info("🔄 Starting comprehensive security scan...")
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # S3 Scan
        status_text.text("🔍 Scanning S3 buckets...")
        progress_bar.progress(25)
        s3_results = scan_s3()
        
        # IAM Scan
        status_text.text("🔍 Scanning IAM policies...")
        progress_bar.progress(50)
        iam_results = scan_iam_permissions()
        
        # EC2 Scan
        status_text.text("🔍 Scanning EC2 security groups...")
        progress_bar.progress(75)
        ec2_results = scan_ec2_security_groups()
        
        progress_bar.progress(100)
        status_text.text("✅ Scan completed successfully!")
        
        st.success("🎉 All scans completed! Results are now available.")
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Scan failed: {str(e)}")

def display_overview():
    """Display main dashboard overview"""
    st.markdown('<div class="main-header"><h1>🛡️ CloudSecVision Security Dashboard</h1></div>', unsafe_allow_html=True)
    
    results = load_scan_results()
    
    if not results:
        st.warning("📊 No scan results found. Please run a security scan first.")
        if st.button("🚀 Run Security Scan", type="primary"):
            run_scans()
        return
    
    # Calculate overall metrics
    total_issues = 0
    critical_issues = 0
    high_issues = 0
    services_scanned = len(results)
    
    for service, issues in results.items():
        if isinstance(issues, list):
            total_issues += len(issues)
            for issue in issues:
                severity = issue.get('Severity', '').upper()
                if severity == 'CRITICAL':
                    critical_issues += 1
                elif severity == 'HIGH':
                    high_issues += 1
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🏢 Services Scanned", services_scanned)
    
    with col2:
        st.metric("⚠️ Total Issues", total_issues)
    
    with col3:
        st.metric("🚨 Critical Issues", critical_issues, delta=None if critical_issues == 0 else "Needs Attention")
    
    with col4:
        st.metric("📈 High Priority", high_issues)
    
    # Security Score
    if total_issues == 0:
        security_score = 100
        score_color = "green"
    elif critical_issues > 0:
        security_score = max(0, 100 - (critical_issues * 25 + high_issues * 10))
        score_color = "red"
    else:
        security_score = max(20, 100 - (high_issues * 15 + (total_issues - high_issues) * 5))
        score_color = "orange" if security_score < 70 else "green"
    
    st.markdown("---")
    col1, col2 = st.columns([1, 2])
    
    with col1:
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = security_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Security Score"},
            delta = {'reference': 100},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': score_color},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "lightgreen"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Issues by service chart
        service_data = []
        for service, issues in results.items():
            if isinstance(issues, list):
                service_data.append({
                    'Service': service.upper(),
                    'Issues': len(issues)
                })
        
        if service_data:
            df = pd.DataFrame(service_data)
            fig = px.bar(df, x='Service', y='Issues', 
                        title="Issues by Service",
                        color='Issues',
                        color_continuous_scale='Reds')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    # Recent Activity
    st.markdown("---")
    st.subheader("📋 Recent Security Findings")
    
    all_issues = []
    for service, issues in results.items():
        if isinstance(issues, list):
            for issue in issues:
                issue['Service'] = service.upper()
                all_issues.append(issue)
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    all_issues.sort(key=lambda x: severity_order.get(x.get('Severity', 'LOW'), 4))
    
    # Display top issues
    for i, issue in enumerate(all_issues[:10]):
        severity = issue.get('Severity', 'UNKNOWN').upper()
        service = issue.get('Service', 'UNKNOWN')
        
        if severity == 'CRITICAL':
            alert_class = "critical-alert"
            icon = "🚨"
        elif severity == 'HIGH':
            alert_class = "warning-alert"
            icon = "⚠️"
        elif severity == 'MEDIUM':
            alert_class = "info-alert"
            icon = "ℹ️"
        else:
            alert_class = "success-alert"
            icon = "🔵"
        
        issue_text = issue.get('Issue', 'Unknown issue')
        st.markdown(f"""
        <div class="{alert_class}">
            <strong>{icon} {service} - {severity}</strong><br>
            {issue_text}
        </div>
        """, unsafe_allow_html=True)

def display_iam_page():
    """Display dedicated IAM security analysis page"""
    st.markdown('<div class="main-header"><h1>🔐 IAM Security Analysis</h1></div>', unsafe_allow_html=True)
    
    # Load IAM results
    results = load_scan_results()
    iam_results = results.get('iam', [])
    
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.subheader("🎛️ Controls")
        if st.button("🔄 Refresh IAM Scan", type="primary"):
            with st.spinner("Scanning IAM policies..."):
                try:
                    iam_results = scan_iam_permissions()
                    st.success("✅ IAM scan completed!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Scan failed: {str(e)}")
        
        if st.button("🤖 Generate AI Report"):
            if iam_results:
                with st.spinner("Generating AI analysis..."):
                    ai_report = generate_iam_report(iam_results)
                    st.session_state['iam_ai_report'] = ai_report
                    st.success("✅ AI report generated!")
            else:
                st.warning("No IAM issues found to analyze.")
    
    with col1:
        st.subheader("📊 IAM Security Overview")
        
        if not iam_results:
            st.success("✅ No IAM security issues detected!")
            st.info("Your IAM policies appear to follow security best practices.")
        else:
            # Display metrics
            total_policies = len(iam_results)
            
            col1_1, col1_2 = st.columns(2)
            with col1_1:
                st.metric("🚨 Overly Permissive Policies", total_policies)
            with col1_2:
                st.metric("⚠️ Risk Level", "HIGH" if total_policies > 5 else "MEDIUM")
            
            # Display detailed issues
            st.subheader("🔍 Detailed Issues")
            for i, issue in enumerate(iam_results, 1):
                with st.expander(f"Policy #{i}: {issue.get('PolicyName', 'Unknown')}"):
                    st.write(f"**Policy ARN:** `{issue.get('Arn', 'Unknown')}`")
                    st.write(f"**Issue:** {issue.get('Issue', 'Unknown issue')}")
                    st.warning("⚠️ This policy grants overly broad permissions and should be reviewed.")
    
    # AI Analysis Report
    if 'iam_ai_report' in st.session_state:
        st.markdown("---")
        st.subheader("🤖 AI Security Analysis Report")
        
        report = st.session_state['iam_ai_report']
        
        # Risk Assessment
        risk_level = report.get('risk_assessment', 'UNKNOWN')
        if risk_level == 'CRITICAL':
            st.error(f"🚨 Risk Level: {risk_level}")
        elif risk_level == 'HIGH':
            st.warning(f"⚠️ Risk Level: {risk_level}")
        elif risk_level == 'MEDIUM':
            st.info(f"ℹ️ Risk Level: {risk_level}")
        else:
            st.success(f"✅ Risk Level: {risk_level}")
        
        # Executive Summary
        st.subheader("📋 Executive Summary")
        st.write(report.get('summary', 'No summary available'))
        
        # Detailed Analysis
        st.subheader("🔬 Detailed Analysis")
        st.write(report.get('detailed_analysis', 'No detailed analysis available'))
        
        # Recommendations and Actions
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("💡 Recommendations")
            recommendations = report.get('recommendations', [])
            for rec in recommendations:
                st.write(f"• {rec}")
        
        with col2:
            st.subheader("🚨 Priority Actions")
            actions = report.get('priority_actions', [])
            for action in actions:
                st.write(f"• {action}")
        
        # Compliance Status
        st.subheader("📜 Compliance Status")
        compliance = report.get('compliance_status', 'UNKNOWN')
        if compliance == 'COMPLIANT':
            st.success(f"✅ Status: {compliance}")
        elif compliance == 'PARTIALLY_COMPLIANT':
            st.warning(f"⚠️ Status: {compliance}")
        else:
            st.error(f"❌ Status: {compliance}")

def main():
    # Sidebar navigation
    st.sidebar.title("🛡️ CloudSecVision")
    
    # Navigation
    page = st.sidebar.selectbox(
        "📍 Navigate to:",
        ["🏠 Dashboard Overview", "🔐 IAM Analysis", "☁️ S3 Analysis", "🖥️ EC2 Analysis"]
    )
    
    # Display current page
    if page == "🏠 Dashboard Overview":
        display_overview()
    elif page == "🔐 IAM Analysis":
        display_iam_page()
    elif page == "☁️ S3 Analysis":
        st.markdown('<div class="main-header"><h1>☁️ S3 Security Analysis</h1></div>', unsafe_allow_html=True)
        st.info("🚧 S3 detailed analysis page coming soon!")
    elif page == "🖥️ EC2 Analysis":
        st.markdown('<div class="main-header"><h1>🖥️ EC2 Security Analysis</h1></div>', unsafe_allow_html=True)
        st.info("🚧 EC2 detailed analysis page coming soon!")
    
    # Sidebar info
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 Quick Actions")
    
    if st.sidebar.button("🔄 Run Full Scan"):
        run_scans()
    
    if st.sidebar.button("🧹 Clear Cache"):
        st.cache_data.clear()
        st.success("✅ Cache cleared!")
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ About")
    st.sidebar.info("CloudSecVision v2.0\n\nAdvanced cloud security scanning with AI-powered analysis.")

if __name__ == "__main__":
    main()
