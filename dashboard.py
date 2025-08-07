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
from analysis.ai_analyzer import analyze_security_issues

def get_specific_recommendations(vulnerability_type, vulnerability_data):
    """Get AI recommendations for specific vulnerability"""
    try:
        prompt = f"""
        Analyze this specific {vulnerability_type} security vulnerability and provide a brief, actionable recommendation.

        Vulnerability Data: {json.dumps(vulnerability_data, indent=2)}

        Please respond with a JSON object containing:
        {{
            "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
            "recommendation": "A specific actionable recommendation for this vulnerability",
            "immediate_action": "One immediate action to take"
        }}

        Only return the JSON object, nothing else.
        """
        
        import requests
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': 'llama3.2:3b',
                'prompt': prompt,
                'stream': False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_text = result.get('response', '')
            
            # Extract JSON from response
            start_idx = ai_text.find('{')
            end_idx = ai_text.rfind('}') + 1
            if start_idx != -1 and end_idx != -1:
                json_str = ai_text[start_idx:end_idx]
                ai_rec = json.loads(json_str)
                return ai_rec
        
    except Exception as e:
        print(f"AI recommendation failed: {e}")
    
    # Fallback recommendations
    fallbacks = {
        'EC2': {
            'severity': 'HIGH',
            'recommendation': 'Restrict security group rules to specific IP ranges instead of 0.0.0.0/0',
            'immediate_action': 'Review and update security group rules'
        },
        'IAM': {
            'severity': 'HIGH', 
            'recommendation': 'Apply principle of least privilege by removing wildcard permissions',
            'immediate_action': 'Review and restrict IAM policy permissions'
        },
        'S3': {
            'severity': 'CRITICAL',
            'recommendation': 'Remove public access and implement bucket policies with specific permissions',
            'immediate_action': 'Make bucket private immediately'
        }
    }
    return fallbacks.get(vulnerability_type, fallbacks['EC2'])

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
</style>
""", unsafe_allow_html=True)

def load_scan_results():
    """Load scan results from JSON files"""
    results = {}
    results_dir = "/home/youcef/Documents/M1/cloudsecvision/scan/results"
    
    # Load EC2
    ec2_file = os.path.join(results_dir, "ec2_scan.json")
    if os.path.exists(ec2_file):
        with open(ec2_file, 'r') as f:
            results['ec2'] = json.load(f)
    else:
        results['ec2'] = []
    
    # Load IAM
    iam_file = os.path.join(results_dir, "iam_scan_report.json")
    if os.path.exists(iam_file):
        with open(iam_file, 'r') as f:
            results['iam'] = json.load(f)
    else:
        results['iam'] = []
    
    # Load S3
    s3_file = os.path.join(results_dir, "s3_scan_report.json")
    if os.path.exists(s3_file):
        with open(s3_file, 'r') as f:
            results['s3'] = json.load(f)
    else:
        results['s3'] = []
    
    return results

def run_scans():
    """Execute all security scans"""
    with st.spinner('🔍 Scanning in progress...'):
        progress_bar = st.progress(0)
        
        # EC2 Scan
        st.text("Scanning EC2 Security Groups...")
        ec2_results = scan_ec2_security_groups()
        progress_bar.progress(33)
        
        # IAM Scan
        st.text("Scanning IAM Policies...")
        iam_results = scan_iam_permissions()
        progress_bar.progress(66)
        
        # S3 Scan
        st.text("Scanning S3 Buckets...")
        s3_results = scan_s3()
        progress_bar.progress(100)
        
    st.success("✅ Scan completed!")
    return {
        'ec2': ec2_results,
        'iam': iam_results,
        's3': s3_results
    }

def display_overview(results):
    """Display overview of results"""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ CloudSecVision Dashboard</h1>
        <p>Real-time AWS Security Monitoring</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Calculate metrics
    total_issues = len(results.get('ec2', [])) + len(results.get('iam', [])) + len(results.get('s3', []))
    ec2_issues = len(results.get('ec2', []))
    iam_issues = len(results.get('iam', []))
    s3_issues = len(results.get('s3', []))
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🚨 Total Issues",
            value=total_issues,
            delta=f"Last update: {datetime.now().strftime('%H:%M')}"
        )
    
    with col2:
        st.metric(
            label="🖥️ EC2 Issues",
            value=ec2_issues,
            delta="Security Groups"
        )
    
    with col3:
        st.metric(
            label="👤 IAM Issues", 
            value=iam_issues,
            delta="Policies"
        )
    
    with col4:
        st.metric(
            label="🪣 S3 Issues",
            value=s3_issues,
            delta="Buckets"
        )
    
    # Donut chart for issue distribution
    if total_issues > 0:
        fig = go.Figure(data=[go.Pie(
            labels=['EC2', 'IAM', 'S3'],
            values=[ec2_issues, iam_issues, s3_issues],
            hole=.3,
            marker_colors=['#ff6b6b', '#4ecdc4', '#45b7d1']
        )])
        fig.update_layout(
            title="Vulnerability Distribution by Service",
            showlegend=True,
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Global risk level
    if total_issues == 0:
        st.markdown("""
        <div class="success-alert">
            <h3>✅ Excellent! No vulnerabilities detected</h3>
            <p>Your AWS infrastructure appears to be secure according to our analysis.</p>
        </div>
        """, unsafe_allow_html=True)
    elif total_issues <= 3:
        st.markdown("""
        <div class="warning-alert">
            <h3>⚠️ Moderate Risk</h3>
            <p>Some vulnerabilities have been detected. We recommend fixing them.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="critical-alert">
            <h3>🚨 High Risk</h3>
            <p>Multiple critical vulnerabilities detected. Immediate action required!</p>
        </div>
        """, unsafe_allow_html=True)
    
    # AI Summary Analysis for overview
    if total_issues > 0:
        st.subheader("🤖 AI Security Summary")
        with st.spinner("🤖 Generating security summary..."):
            try:
                ai_summary = analyze_security_issues(results)
                if ai_summary:
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        severity = ai_summary.get('severity', 'HIGH')
                        st.metric("Overall Severity", f"🔴 {severity}" if severity == 'CRITICAL' else f"🟠 {severity}")
                    
                    with col2:
                        risk_score = ai_summary.get('risk_score', 0)
                        st.metric("Risk Score", f"{risk_score}/100")
                    
                    with col3:
                        recommendations_count = len(ai_summary.get('recommendations', []))
                        st.metric("AI Recommendations", recommendations_count)
                    
                    # Quick AI insights
                    top_priority = ai_summary.get('top_priorities', ['Review security configuration'])[0]
                    st.info(f"🎯 **Top Priority:** {top_priority}")
                    
            except Exception as e:
                st.warning(f"AI summary unavailable: {str(e)}")
                st.caption("💡 Make sure Ollama is running for AI analysis")

def display_ec2_details(ec2_results):
    """Display EC2 vulnerability details"""
    st.header("🖥️ EC2 Security Groups Analysis")
    
    if not ec2_results:
        st.success("✅ No EC2 vulnerabilities detected!")
        return
    
    # Convert to DataFrame for display
    df = pd.DataFrame(ec2_results)
    
    # Statistics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Vulnerable Security Groups", len(df['GroupId'].unique()))
    with col2:
        st.metric("Exposed Ports", len(df))
    
    # Detailed table
    st.subheader("Vulnerability Details")
    st.dataframe(df, use_container_width=True)
    
    # AI-powered recommendations for each vulnerability
    st.subheader("🤖 AI Recommendations")
    for _, issue in df.iterrows():
        with st.expander(f"🚨 {issue['GroupName']} - Port {issue['Port']}", expanded=False):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**Security Group:** {issue['GroupId']}")
                st.write(f"**Issue:** {issue['Issue']}")
                st.write(f"**IP Range:** {issue['IpRange']}")
            
            with col2:
                with st.spinner("🤖 Getting AI recommendation..."):
                    ai_rec = get_specific_recommendations('EC2', issue.to_dict())
                    
                    severity = ai_rec.get('severity', 'HIGH')
                    severity_color = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠', 
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(severity, '⚪')
                    
                    st.metric("Severity", f"{severity_color} {severity}")
            
            # AI recommendations
            recommendation = ai_rec.get('recommendation', 'Review security group configuration')
            immediate_action = ai_rec.get('immediate_action', 'Update security group rules')
            
            st.info(f"**💡 AI Recommendation:** {recommendation}")
            st.warning(f"**🚨 Immediate Action:** {immediate_action}")
            
            # AWS CLI command
            st.code(f"""
# AWS CLI to fix this security group:
aws ec2 revoke-security-group-ingress \\
    --group-id {issue['GroupId']} \\
    --protocol tcp \\
    --port {issue['Port']} \\
    --cidr {issue['IpRange']}
            """)
    
    # Chart of most problematic security groups
    if len(df) > 0:
        sg_counts = df['GroupName'].value_counts()
        fig = px.bar(
            x=sg_counts.values,
            y=sg_counts.index,
            orientation='h',
            title="Most Vulnerable Security Groups",
            labels={'x': 'Number of vulnerabilities', 'y': 'Security Group'}
        )
        st.plotly_chart(fig, use_container_width=True)

def display_iam_details(iam_results):
    """Display IAM vulnerability details"""
    st.header("👤 IAM Policies Analysis")
    
    if not iam_results:
        st.success("✅ No overly permissive IAM policies detected!")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(iam_results)
    
    # Metrics
    st.metric("Overly permissive policies", len(df))
    
    # AI-powered recommendations for each policy
    st.subheader("🤖 AI Policy Analysis")
    for _, policy in df.iterrows():
        with st.expander(f"🚨 {policy['PolicyName']}", expanded=False):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**ARN:** {policy['Arn']}")
                st.write(f"**Issue:** {policy['Issue']}")
            
            with col2:
                with st.spinner("🤖 Analyzing policy..."):
                    ai_rec = get_specific_recommendations('IAM', policy.to_dict())
                    
                    severity = ai_rec.get('severity', 'HIGH')
                    severity_color = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠', 
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(severity, '⚪')
                    
                    st.metric("Risk Level", f"{severity_color} {severity}")
            
            # AI recommendations
            recommendation = ai_rec.get('recommendation', 'Review and restrict policy permissions')
            immediate_action = ai_rec.get('immediate_action', 'Apply principle of least privilege')
            
            st.info(f"**💡 AI Recommendation:** {recommendation}")
            st.warning(f"**🚨 Immediate Action:** {immediate_action}")
            
            # Remediation steps
            st.markdown("**🔧 Remediation Steps:**")
            st.markdown("""
            1. Review the policy document for wildcard permissions (*)
            2. Identify the minimum permissions actually needed
            3. Create a new policy version with restricted permissions
            4. Test the new policy with affected users/roles
            5. Set the new version as default
            """)
            
            # AWS CLI command
            policy_name = policy['PolicyName'].replace(' ', '-')
            st.code(f"""
# AWS CLI to review policy:
aws iam get-policy-version \\
    --policy-arn {policy['Arn']} \\
    --version-id v1
            """)

def display_s3_details(s3_results):
    """Display S3 vulnerability details"""
    st.header("🪣 S3 Buckets Analysis")
    
    if not s3_results:
        st.success("✅ No public S3 buckets detected!")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(s3_results)
    
    # Metrics
    st.metric("Public buckets", len(df))
    
    # Critical alert for public buckets
    st.error("🚨 WARNING: S3 buckets are publicly accessible!")
    
    # AI-powered recommendations for each bucket
    st.subheader("🤖 AI Bucket Analysis")
    for _, bucket in df.iterrows():
        with st.expander(f"🚨 {bucket['BucketName']}", expanded=True):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**Bucket Name:** {bucket['BucketName']}")
                st.write(f"**Issue:** {bucket['Issue']}")
            
            with col2:
                with st.spinner("🤖 Analyzing bucket..."):
                    ai_rec = get_specific_recommendations('S3', bucket.to_dict())
                    
                    severity = ai_rec.get('severity', 'CRITICAL')
                    severity_color = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠', 
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(severity, '⚪')
                    
                    st.metric("Risk Level", f"{severity_color} {severity}")
            
            # AI recommendations
            recommendation = ai_rec.get('recommendation', 'Restrict public access immediately')
            immediate_action = ai_rec.get('immediate_action', 'Make bucket private')
            
            st.error(f"**🚨 CRITICAL:** {immediate_action}")
            st.info(f"**💡 AI Recommendation:** {recommendation}")
            
            # Detailed remediation
            st.markdown("**🔒 Security Remediation:**")
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("""
                **Immediate Actions:**
                1. Remove public ACL permissions
                2. Block public access settings
                3. Review bucket policy
                4. Enable access logging
                """)
            
            with col_b:
                st.markdown("""
                **Best Practices:**
                1. Use IAM policies instead of bucket ACLs
                2. Enable versioning and MFA delete
                3. Configure lifecycle policies
                4. Set up CloudTrail monitoring
                """)
            
            # AWS CLI commands
            st.code(f"""
# AWS CLI commands to secure this bucket:

# 1. Remove public ACL
aws s3api put-bucket-acl --bucket {bucket['BucketName']} --acl private

# 2. Block public access
aws s3api put-public-access-block --bucket {bucket['BucketName']} \\
    --public-access-block-configuration \\
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 3. Check bucket policy
aws s3api get-bucket-policy --bucket {bucket['BucketName']}
            """)

def display_recommendations(results, use_ai=True):
    """Display AI-powered security recommendations"""
    st.header("💡 Security Recommendations")
    
    if not use_ai:
        st.info("🤖 AI Analysis is disabled. Showing general recommendations.")
        display_fallback_recommendations()
        return
    
    # Show loading message while analyzing
    with st.spinner("🤖 Analyzing vulnerabilities with Ollama AI..."):
        try:
            # Get AI analysis
            ai_analysis = analyze_security_issues(results)
            
            if ai_analysis:
                # Display AI analysis results
                st.subheader("🤖 AI Analysis Results")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    severity = ai_analysis.get('severity', 'UNKNOWN')
                    severity_color = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠', 
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(severity, '⚪')
                    st.metric("Severity Level", f"{severity_color} {severity}")
                
                with col2:
                    risk_score = ai_analysis.get('risk_score', 0)
                    st.metric("Risk Score", f"{risk_score}/100")
                
                with col3:
                    total_issues = ai_analysis.get('total_issues', 0)
                    st.metric("Total Issues", total_issues)
                
                # Top Priorities section
                priorities = ai_analysis.get('top_priorities', [])
                if priorities:
                    st.subheader("🚨 Top Priorities")
                    for i, priority in enumerate(priorities, 1):
                        st.markdown(f"**{i}.** {priority}")
                
                # AI Recommendations section
                recommendations = ai_analysis.get('recommendations', [])
                if recommendations:
                    st.subheader("🤖 AI Recommendations")
                    for i, rec in enumerate(recommendations, 1):
                        st.markdown(f"**{i}.** {rec}")
                
                # Risk level alert
                if risk_score >= 80:
                    st.error("🚨 **CRITICAL RISK**: Immediate action required!")
                elif risk_score >= 50:
                    st.warning("⚠️ **HIGH RISK**: Action recommended within 24 hours")
                elif risk_score >= 25:
                    st.info("💡 **MODERATE RISK**: Schedule remediation this week")
                else:
                    st.success("✅ **LOW RISK**: Continue monitoring")
            
            else:
                st.error("❌ Failed to get AI analysis")
                display_fallback_recommendations()
                
        except Exception as e:
            st.error(f"❌ AI Analysis Error: {str(e)}")
            st.info("💡 Make sure Ollama is running: `ollama serve`")
            display_fallback_recommendations()
    
    # Additional resources
    st.subheader("📚 Additional Resources")
    st.markdown("""
    - [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
    - [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
    - [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
    - [EC2 Security Groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-groups.html)
    """)

def display_fallback_recommendations():
    """Display fallback recommendations when AI is not available"""
    st.subheader("🔒 General Security Best Practices")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Access Control:**
        - Implement principle of least privilege
        - Use IAM roles instead of users when possible
        - Enable MFA for all users
        - Regularly rotate access keys
        """)
        
    with col2:
        st.markdown("""
        **Network Security:**
        - Restrict Security Group rules
        - Use VPC endpoints for AWS services
        - Enable VPC Flow Logs
        - Implement network segmentation
        """)
    
    st.markdown("""
    **Data Protection:**
    - Enable encryption in transit and at rest
    - Use S3 bucket policies and ACLs properly
    - Enable CloudTrail for audit logging
    - Set up automated security scanning
    """)

def main():
    """Main dashboard function"""
    
    # Sidebar
    st.sidebar.title("🛡️ CloudSecVision")
    st.sidebar.markdown("---")
    
    # Navigation
    page = st.sidebar.selectbox(
        "Navigation",
        ["🏠 Overview", "🖥️ EC2 Details", "👤 IAM Details", "🪣 S3 Details", "💡 Recommendations"]
    )
    
    st.sidebar.markdown("---")
    
    # AI Analysis toggle
    use_ai = st.sidebar.checkbox("🤖 Enable AI Analysis", value=True)
    st.sidebar.caption("Uses Ollama for intelligent recommendations")
    
    st.sidebar.markdown("---")
    
    # Actions
    if st.sidebar.button("🔄 Run New Scan", type="primary"):
        results = run_scans()
        st.rerun()
    
    if st.sidebar.button("📊 Refresh Data"):
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.info("**Last Update:**\n" + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # Load data
    results = load_scan_results()
    
    # Display according to selected page
    if page == "🏠 Overview":
        display_overview(results)
    elif page == "🖥️ EC2 Details":
        display_ec2_details(results.get('ec2', []))
    elif page == "👤 IAM Details":
        display_iam_details(results.get('iam', []))
    elif page == "🪣 S3 Details":
        display_s3_details(results.get('s3', []))
    elif page == "💡 Recommendations":
        display_recommendations(results, use_ai)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        🛡️ CloudSecVision Dashboard - Developed by Youcef | M1 Cloud Security & AWS Project
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
