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
from analysis.ai_analyzer import analyze_security_issues, generate_iam_report, generate_ec2_report, generate_s3_report, display_iam_report, display_ec2_report, display_s3_report

# Page configuration
st.set_page_config(
    page_title="CloudSecVision Dashboard",
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
    
    for service, data in results.items():
        if isinstance(data, list):
            # Format ancien (S3, IAM) - liste d'issues
            total_issues += len(data)
            for issue in data:
                severity = issue.get('Severity', '').upper()
                if severity == 'CRITICAL':
                    critical_issues += 1
                elif severity == 'HIGH':
                    high_issues += 1
        elif isinstance(data, dict):
            # Format nouveau (EC2) - dictionnaire structuré
            if 'findings' in data:
                findings = data.get('findings', [])
                total_issues += len(findings)
                critical_issues += data.get('critical_issues', 0)
                high_issues += data.get('high_issues', 0)
            else:
                # Fallback pour dictionnaire simple
                total_issues += len(data)
    
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
    
    # Security Score - utiliser le score professionnel d'EC2 comme base
    if total_issues == 0:
        security_score = 100
        score_color = "green"
    else:
        # Utiliser le score EC2 s'il existe, sinon calculer
        if 'ec2' in results and isinstance(results['ec2'], dict) and 'security_score' in results['ec2']:
            # Utiliser le score professionnel d'EC2 comme base
            ec2_score = results['ec2']['security_score']
            ec2_issues = len(results['ec2'].get('findings', []))
            # Ajuster selon les autres services
            other_issues = total_issues - ec2_issues
            security_score = max(0, ec2_score - (other_issues * 5))
        else:
            # Calcul fallback pour format ancien
            if critical_issues > 0:
                security_score = max(0, 100 - (critical_issues * 25 + high_issues * 10))
            else:
                security_score = max(20, 100 - (high_issues * 15 + (total_issues - high_issues) * 5))
        
        # Couleur selon le score
        if security_score < 30:
            score_color = "red"
        elif security_score < 70:
            score_color = "orange"
        else:
            score_color = "green"
    
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
        for service, data in results.items():
            if isinstance(data, list):
                # Format ancien (S3, IAM)
                service_data.append({
                    'Service': service.upper(),
                    'Issues': len(data)
                })
            elif isinstance(data, dict):
                # Format nouveau (EC2)
                if 'findings' in data:
                    service_data.append({
                        'Service': service.upper(),
                        'Issues': len(data.get('findings', []))
                    })
                else:
                    service_data.append({
                        'Service': service.upper(),
                        'Issues': len(data)
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
    for service, data in results.items():
        if isinstance(data, list):
            # Format ancien (S3, IAM)
            for issue in data:
                issue['Service'] = service.upper()
                all_issues.append(issue)
        elif isinstance(data, dict):
            # Format nouveau (EC2)
            if 'findings' in data:
                for finding in data.get('findings', []):
                    # Convertir le format EC2 vers le format unifié pour affichage
                    issue = {
                        'Service': service.upper(),
                        'Severity': finding.get('severity', 'UNKNOWN').upper(),
                        'Issue': finding.get('title', 'Unknown Issue'),
                        'Description': finding.get('description', ''),
                        'Resource': finding.get('resource_id', 'Unknown')
                    }
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

def display_s3_page():
    """Display dedicated S3 security analysis page"""
    st.markdown('<div class="main-header"><h1>☁️ S3 Security Analysis</h1></div>', unsafe_allow_html=True)
    
    # Load S3 results
    results = load_scan_results()
    s3_results = results.get('s3', [])
    
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.subheader("🎛️ Controls")
        if st.button("🔄 Refresh S3 Scan", type="primary"):
            with st.spinner("Scanning S3 buckets..."):
                try:
                    s3_results = scan_s3()
                    st.success("✅ S3 scan completed!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Scan failed: {str(e)}")
        
        if st.button("🤖 Generate AI Report"):
            if s3_results:
                with st.spinner("Generating AI analysis..."):
                    ai_report = generate_s3_report(s3_results)
                    st.session_state['s3_ai_report'] = ai_report
                    st.success("✅ AI report generated!")
            else:
                st.warning("No S3 issues found to analyze.")
    
    with col1:
        st.subheader("📊 S3 Security Overview")
        
        if not s3_results:
            st.success("✅ No S3 security issues detected!")
            st.info("Your S3 buckets appear to follow security best practices.")
        else:
            # Display metrics
            total_issues = len(s3_results)
            critical_issues = len([i for i in s3_results if i.get('Severity') == 'CRITICAL'])
            high_issues = len([i for i in s3_results if i.get('Severity') == 'HIGH'])
            
            col1_1, col1_2, col1_3 = st.columns(3)
            with col1_1:
                st.metric("🚨 Total Issues", total_issues)
            with col1_2:
                st.metric("⚠️ Critical", critical_issues, delta="Needs Attention" if critical_issues > 0 else None)
            with col1_3:
                st.metric("🟠 High", high_issues)
            
            # Group by bucket
            buckets = {}
            for issue in s3_results:
                bucket = issue.get('BucketName', 'Unknown')
                if bucket not in buckets:
                    buckets[bucket] = []
                buckets[bucket].append(issue)
            
            # Display buckets with issues
            st.subheader("🪣 Affected Buckets")
            
            for bucket_name, issues in buckets.items():
                with st.expander(f"Bucket: {bucket_name} ({len(issues)} issues)"):
                    # Group by severity
                    by_severity = {
                        'CRITICAL': [i for i in issues if i.get('Severity') == 'CRITICAL'],
                        'HIGH': [i for i in issues if i.get('Severity') == 'HIGH'],
                        'MEDIUM': [i for i in issues if i.get('Severity') == 'MEDIUM'],
                        'LOW': [i for i in issues if i.get('Severity') == 'LOW']
                    }
                    
                    for severity, sev_issues in by_severity.items():
                        if sev_issues:
                            if severity == 'CRITICAL':
                                st.error(f"🚨 {severity}: {len(sev_issues)} issues")
                            elif severity == 'HIGH':
                                st.warning(f"⚠️ {severity}: {len(sev_issues)} issues")
                            elif severity == 'MEDIUM':
                                st.info(f"ℹ️ {severity}: {len(sev_issues)} issues")
                            else:
                                st.success(f"✓ {severity}: {len(sev_issues)} issues")
                            
                            for i, issue in enumerate(sev_issues, 1):
                                st.write(f"**Issue #{i}:** {issue.get('Issue', 'Unknown issue')}")
                                if 'Recommendation' in issue:
                                    st.write(f"*Recommendation:* {issue['Recommendation']}")
    
    # AI Analysis Report
    if 's3_ai_report' in st.session_state:
        st.markdown("---")
        st.subheader("🤖 AI Security Analysis Report")
        
        report = st.session_state['s3_ai_report']
        
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

def display_ec2_page():
    """Display dedicated EC2 security analysis page"""
    st.markdown('<div class="main-header"><h1>🖥️ EC2 Security Analysis</h1></div>', unsafe_allow_html=True)
    
    # Load EC2 results
    results = load_scan_results()
    ec2_results = results.get('ec2', [])
    
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.subheader("🎛️ Controls")
        if st.button("🔄 Refresh EC2 Scan", type="primary"):
            with st.spinner("Scanning EC2 security groups..."):
                try:
                    ec2_results = scan_ec2_security_groups()
                    st.success("✅ EC2 scan completed!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Scan failed: {str(e)}")
        
        if st.button("🤖 Generate AI Report"):
            if ec2_results:
                with st.spinner("Generating AI analysis..."):
                    ai_report = generate_ec2_report(ec2_results)
                    st.session_state['ec2_ai_report'] = ai_report
                    st.success("✅ AI report generated!")
            else:
                st.warning("No EC2 issues found to analyze.")
    
    with col1:
        st.subheader("📊 EC2 Security Overview")
        
        if not ec2_results:
            st.success("✅ No EC2 security issues detected!")
            st.info("Your EC2 security groups appear to follow security best practices.")
        else:
            # Handle both old format (list) and new format (dict with findings)
            if isinstance(ec2_results, dict):
                # New structured format
                findings = ec2_results.get('findings', [])
                total_issues = ec2_results.get('total_issues', len(findings))
                security_score = ec2_results.get('security_score', 0)
                critical_issues = ec2_results.get('critical_issues', 0)
                high_issues = ec2_results.get('high_issues', 0)
                
                # Display enhanced metrics
                col1_1, col1_2, col1_3 = st.columns(3)
                with col1_1:
                    st.metric("🚨 Total Issues", total_issues)
                with col1_2:
                    st.metric("🔥 Critical + High", critical_issues + high_issues, 
                             delta=None if (critical_issues + high_issues) == 0 else "High Priority")
                with col1_3:
                    st.metric("📊 Security Score", f"{security_score}/100", 
                             delta=f"{'Good' if security_score >= 70 else 'Needs Improvement'}")
                
                # Display detailed findings
                if findings:
                    st.subheader("🔍 Security Findings")
                    for i, finding in enumerate(findings, 1):
                        severity = finding.get('severity', 'UNKNOWN')
                        title = finding.get('title', 'Unknown Issue')
                        
                        # Color code by severity
                        severity_color = {
                            'CRITICAL': '🔴',
                            'HIGH': '🟠', 
                            'MEDIUM': '🟡',
                            'LOW': '🟢'
                        }.get(severity, '⚪')
                        
                        with st.expander(f"{severity_color} [{severity}] {title}"):
                            st.write(f"**Resource:** `{finding.get('resource_id', 'Unknown')}`")
                            st.write(f"**Type:** {finding.get('resource_type', 'Unknown')}")
                            st.write(f"**Category:** {finding.get('category', 'Unknown')}")
                            st.write(f"**Description:** {finding.get('description', 'No description available')}")
                            st.write(f"**Recommendation:** {finding.get('recommendation', 'No recommendation available')}")
                            if finding.get('compliance_impact'):
                                st.warning(f"**Compliance Impact:** {finding.get('compliance_impact')}")
            else:
                # Old format (list) - for backwards compatibility
                total_issues = len(ec2_results)
                ssh_open = sum(1 for issue in ec2_results if "SSH port 22 open" in str(issue.get('Issue', '')))
                
                col1_1, col1_2 = st.columns(2)
                with col1_1:
                    st.metric("🚨 Security Issues", total_issues)
                with col1_2:
                    st.metric("⚠️ SSH Exposed", ssh_open, delta=None if ssh_open == 0 else "Needs Attention")
                
                # Display detailed issues
                st.subheader("🔍 Detailed Issues")
                for i, issue in enumerate(ec2_results, 1):
                    with st.expander(f"Security Group #{i}: {issue.get('GroupName', 'Unknown')}"):
                        st.write(f"**Group ID:** `{issue.get('GroupId', 'Unknown')}`")
                        st.write(f"**Port:** {issue.get('Port', 'Unknown')}")
                        st.write(f"**IP Range:** `{issue.get('IpRange', 'Unknown')}`")
                    st.write(f"**Issue:** {issue.get('Issue', 'Unknown issue')}")
                    st.warning("⚠️ This security group has potentially dangerous configurations.")
    
    # AI Analysis Report
    if 'ec2_ai_report' in st.session_state:
        st.markdown("---")
        st.subheader("🤖 AI Security Analysis Report")
        
        report = st.session_state['ec2_ai_report']
        
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
        display_s3_page()
    elif page == "🖥️ EC2 Analysis":
        display_ec2_page()
    
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
