import boto3
import json
import os
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
import logging

class IAMSecurityScanner:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')
        self.results = {
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'findings': []
        }
        
        # Dangerous actions and their risk levels
        self.DANGEROUS_ACTIONS = {
            '*': {'risk': 'CRITICAL', 'name': 'Full Admin Access'},
            'iam:*': {'risk': 'CRITICAL', 'name': 'Full IAM Access'},
            's3:*': {'risk': 'HIGH', 'name': 'Full S3 Access'},
            'ec2:*': {'risk': 'HIGH', 'name': 'Full EC2 Access'},
            'rds:*': {'risk': 'HIGH', 'name': 'Full RDS Access'},
            'lambda:*': {'risk': 'HIGH', 'name': 'Full Lambda Access'},
            'iam:CreateUser': {'risk': 'HIGH', 'name': 'Create IAM Users'},
            'iam:CreateRole': {'risk': 'HIGH', 'name': 'Create IAM Roles'},
            'iam:AttachUserPolicy': {'risk': 'HIGH', 'name': 'Attach User Policies'},
            'iam:AttachRolePolicy': {'risk': 'HIGH', 'name': 'Attach Role Policies'},
            'iam:PutUserPolicy': {'risk': 'HIGH', 'name': 'Put Inline User Policy'},
            'iam:PutRolePolicy': {'risk': 'HIGH', 'name': 'Put Inline Role Policy'},
            'sts:AssumeRole': {'risk': 'MEDIUM', 'name': 'Assume Role'},
            'ec2:TerminateInstances': {'risk': 'HIGH', 'name': 'Terminate EC2 Instances'},
            'rds:DeleteDBInstance': {'risk': 'HIGH', 'name': 'Delete RDS Instance'},
            's3:DeleteBucket': {'risk': 'HIGH', 'name': 'Delete S3 Bucket'},
            'kms:*': {'risk': 'HIGH', 'name': 'Full KMS Access'},
            'secretsmanager:*': {'risk': 'HIGH', 'name': 'Full Secrets Manager Access'}
        }
        
        # High-privilege AWS managed policies
        self.HIGH_PRIVILEGE_POLICIES = {
            'arn:aws:iam::aws:policy/AdministratorAccess': 'CRITICAL',
            'arn:aws:iam::aws:policy/PowerUserAccess': 'HIGH',
            'arn:aws:iam::aws:policy/IAMFullAccess': 'CRITICAL',
            'arn:aws:iam::aws:policy/AmazonS3FullAccess': 'HIGH',
            'arn:aws:iam::aws:policy/AmazonEC2FullAccess': 'HIGH',
            'arn:aws:iam::aws:policy/AmazonRDSFullAccess': 'HIGH'
        }

    def add_finding(self, severity, category, title, description, resource_id, resource_type='IAMPolicy', recommendation='', compliance_impact=''):
        """Add a security finding with structured format"""
        finding = {
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'resource_id': resource_id,
            'resource_type': resource_type,
            'recommendation': recommendation,
            'compliance_impact': compliance_impact,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        self.results['findings'].append(finding)
        self.results['total_issues'] += 1
        
        if severity == 'CRITICAL':
            self.results['critical_issues'] += 1
        elif severity == 'HIGH':
            self.results['high_issues'] += 1
        elif severity == 'MEDIUM':
            self.results['medium_issues'] += 1
        else:
            self.results['low_issues'] += 1

    def scan_iam_policies(self):
        """Comprehensive IAM policy vulnerability scan"""
        print("🔍 Scanning IAM Policies for vulnerabilities...")
        
        try:
            # Scan customer managed policies
            policies = self.iam.list_policies(Scope='Local', OnlyAttached=False)['Policies']
            
            for policy in policies:
                self._analyze_policy(policy)
                
            # Scan AWS managed policies attached to users/roles
            self._scan_attached_aws_policies()
            
        except ClientError as e:
            print(f"❌ Error scanning IAM policies: {e}")

    def _analyze_policy(self, policy):
        """Analyze individual IAM policy for security issues"""
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        
        try:
            # Get policy document
            version_id = policy['DefaultVersionId']
            policy_version = self.iam.get_policy_version(
                PolicyArn=policy_arn, 
                VersionId=version_id
            )
            policy_doc = policy_version['PolicyVersion']['Document']
            
            # Check for overly permissive statements
            self._check_permissive_statements(policy_doc, policy_name, policy_arn)
            
            # Check for dangerous actions
            self._check_dangerous_actions(policy_doc, policy_name, policy_arn)
            
            # Check for resource wildcards
            self._check_resource_wildcards(policy_doc, policy_name, policy_arn)
            
            # Check for unused policies
            self._check_unused_policies(policy, policy_name, policy_arn)
            
        except ClientError as e:
            print(f"Warning: Could not analyze policy {policy_name}: {e}")

    def _check_permissive_statements(self, policy_doc, policy_name, policy_arn):
        """Check for overly permissive policy statements"""
        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                
                # Normalize to lists
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                
                # Check for wildcard actions and resources combination
                if '*' in actions and '*' in resources:
                    self.add_finding(
                        severity='CRITICAL',
                        category='Access Control',
                        title='Full Administrative Access Policy',
                        description=f'Policy {policy_name} grants full administrative access with Action:* and Resource:*',
                        resource_id=policy_arn,
                        recommendation='Replace with specific actions and resources following least privilege principle',
                        compliance_impact='Violates SOC 2 CC6.3 and CIS AWS Benchmark 1.22'
                    )
                
                # Check for wildcard actions only
                elif '*' in actions:
                    self.add_finding(
                        severity='HIGH',
                        category='Access Control',
                        title='Wildcard Action Policy',
                        description=f'Policy {policy_name} uses wildcard (*) in Action field',
                        resource_id=policy_arn,
                        recommendation='Specify exact actions needed instead of using wildcards',
                        compliance_impact='Increases risk of privilege escalation'
                    )
                
                # Check for wildcard resources only
                elif '*' in resources:
                    self.add_finding(
                        severity='MEDIUM',
                        category='Access Control',
                        title='Wildcard Resource Policy',
                        description=f'Policy {policy_name} uses wildcard (*) in Resource field',
                        resource_id=policy_arn,
                        recommendation='Specify exact resources (ARNs) instead of using wildcards',
                        compliance_impact='May allow access to unintended resources'
                    )

    def _check_dangerous_actions(self, policy_doc, policy_name, policy_arn):
        """Check for dangerous IAM actions"""
        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if action in self.DANGEROUS_ACTIONS:
                        action_info = self.DANGEROUS_ACTIONS[action]
                        self.add_finding(
                            severity=action_info['risk'],
                            category='Privilege Escalation',
                            title=f'Dangerous Action: {action_info["name"]}',
                            description=f'Policy {policy_name} grants dangerous action: {action}',
                            resource_id=policy_arn,
                            recommendation=f'Review necessity of {action} permission and restrict if possible',
                            compliance_impact='High risk of privilege escalation or data breach'
                        )

    def _check_resource_wildcards(self, policy_doc, policy_name, policy_arn):
        """Check for overly broad resource specifications"""
        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                resources = stmt.get('Resource', [])
                
                if isinstance(resources, str):
                    resources = [resources]
                
                for resource in resources:
                    # Check for cross-account access
                    if '::*:' in resource or resource.endswith(':*'):
                        self.add_finding(
                            severity='MEDIUM',
                            category='Access Control',
                            title='Cross-Account Resource Access',
                            description=f'Policy {policy_name} may allow cross-account access with resource: {resource}',
                            resource_id=policy_arn,
                            recommendation='Specify exact account IDs and resource names',
                            compliance_impact='Potential unauthorized cross-account access'
                        )

    def _check_unused_policies(self, policy, policy_name, policy_arn):
        """Check for unused IAM policies"""
        if policy['AttachmentCount'] == 0:
            self.add_finding(
                severity='LOW',
                category='Resource Management',
                title='Unused IAM Policy',
                description=f'Policy {policy_name} is not attached to any users, groups, or roles',
                resource_id=policy_arn,
                recommendation='Remove unused policies to reduce management overhead',
                compliance_impact='Increases complexity and potential for misconfiguration'
            )

    def _scan_attached_aws_policies(self):
        """Scan for high-privilege AWS managed policies"""
        try:
            # Check users
            users = self.iam.list_users()['Users']
            for user in users:
                attached_policies = self.iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                for policy in attached_policies:
                    if policy['PolicyArn'] in self.HIGH_PRIVILEGE_POLICIES:
                        severity = self.HIGH_PRIVILEGE_POLICIES[policy['PolicyArn']]
                        self.add_finding(
                            severity=severity,
                            category='Access Control',
                            title='High-Privilege AWS Managed Policy',
                            description=f'User {user["UserName"]} has high-privilege policy {policy["PolicyName"]} attached',
                            resource_id=user['UserName'],
                            resource_type='IAMUser',
                            recommendation='Review if full access is necessary, consider using more restrictive policies',
                            compliance_impact='Violates principle of least privilege'
                        )
            
            # Check roles
            roles = self.iam.list_roles()['Roles']
            for role in roles:
                # Skip AWS service roles
                if role['RoleName'].startswith('aws-'):
                    continue
                    
                attached_policies = self.iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                for policy in attached_policies:
                    if policy['PolicyArn'] in self.HIGH_PRIVILEGE_POLICIES:
                        severity = self.HIGH_PRIVILEGE_POLICIES[policy['PolicyArn']]
                        self.add_finding(
                            severity=severity,
                            category='Access Control',
                            title='High-Privilege AWS Managed Policy on Role',
                            description=f'Role {role["RoleName"]} has high-privilege policy {policy["PolicyName"]} attached',
                            resource_id=role['RoleName'],
                            resource_type='IAMRole',
                            recommendation='Review if full access is necessary for this role',
                            compliance_impact='Violates principle of least privilege'
                        )
                        
        except ClientError as e:
            print(f"Warning: Could not scan attached AWS policies: {e}")

    def scan_iam_users(self):
        """Scan IAM users for security issues"""
        print("🔍 Scanning IAM Users for vulnerabilities...")
        
        try:
            users = self.iam.list_users()['Users']
            
            for user in users:
                user_name = user['UserName']
                
                # Check for users without MFA
                self._check_user_mfa(user, user_name)
                
                # Check for old access keys
                self._check_access_keys_age(user_name)
                
                # Check for console access without MFA
                self._check_console_access_mfa(user_name)
                
                # Check for programmatic access patterns
                self._check_programmatic_access(user_name)
                
        except ClientError as e:
            print(f"❌ Error scanning IAM users: {e}")

    def _check_user_mfa(self, user, user_name):
        """Check if user has MFA enabled"""
        try:
            mfa_devices = self.iam.list_mfa_devices(UserName=user_name)['MFADevices']
            if not mfa_devices:
                # Check if user has console access
                try:
                    login_profile = self.iam.get_login_profile(UserName=user_name)
                    self.add_finding(
                        severity='HIGH',
                        category='Authentication',
                        title='Console User Without MFA',
                        description=f'User {user_name} has console access but no MFA device configured',
                        resource_id=user_name,
                        resource_type='IAMUser',
                        recommendation='Enable MFA for all users with console access',
                        compliance_impact='Violates CIS AWS Benchmark 1.2 and SOC 2 requirements'
                    )
                except ClientError:
                    # No login profile, check if they have access keys
                    access_keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                    if access_keys:
                        self.add_finding(
                            severity='MEDIUM',
                            category='Authentication',
                            title='Programmatic User Without MFA',
                            description=f'User {user_name} has access keys but no MFA device configured',
                            resource_id=user_name,
                            resource_type='IAMUser',
                            recommendation='Consider using roles instead of long-term access keys',
                            compliance_impact='Increased risk if credentials are compromised'
                        )
        except ClientError as e:
            print(f"Warning: Could not check MFA for user {user_name}: {e}")

    def _check_access_keys_age(self, user_name):
        """Check for old access keys"""
        try:
            access_keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            
            for key in access_keys:
                key_age = (datetime.now(timezone.utc).replace(tzinfo=None) - key['CreateDate'].replace(tzinfo=None)).days
                
                if key_age > 90:  # Keys older than 90 days
                    severity = 'HIGH' if key_age > 365 else 'MEDIUM'
                    self.add_finding(
                        severity=severity,
                        category='Key Management',
                        title='Old Access Key',
                        description=f'User {user_name} has access key {key["AccessKeyId"]} that is {key_age} days old',
                        resource_id=key['AccessKeyId'],
                        resource_type='AccessKey',
                        recommendation='Rotate access keys regularly (every 90 days)',
                        compliance_impact='Old keys increase security risk if compromised'
                    )
        except ClientError as e:
            print(f"Warning: Could not check access keys for user {user_name}: {e}")

    def _check_console_access_mfa(self, user_name):
        """Check console access patterns"""
        try:
            login_profile = self.iam.get_login_profile(UserName=user_name)
            
            # Check password age
            password_age = (datetime.now(timezone.utc).replace(tzinfo=None) - login_profile['LoginProfile']['CreateDate'].replace(tzinfo=None)).days
            
            if password_age > 90:
                self.add_finding(
                    severity='MEDIUM',
                    category='Authentication',
                    title='Old Console Password',
                    description=f'User {user_name} has not changed console password for {password_age} days',
                    resource_id=user_name,
                    resource_type='IAMUser',
                    recommendation='Implement password rotation policy',
                    compliance_impact='Old passwords increase risk of credential compromise'
                )
                
        except ClientError:
            # No console access
            pass

    def _check_programmatic_access(self, user_name):
        """Check programmatic access patterns"""
        try:
            # Check for both console and programmatic access
            has_console = False
            has_keys = False
            
            try:
                self.iam.get_login_profile(UserName=user_name)
                has_console = True
            except ClientError:
                pass
            
            access_keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            if access_keys:
                has_keys = True
            
            if has_console and has_keys:
                self.add_finding(
                    severity='MEDIUM',
                    category='Access Control',
                    title='Mixed Access Type User',
                    description=f'User {user_name} has both console and programmatic access',
                    resource_id=user_name,
                    resource_type='IAMUser',
                    recommendation='Separate human users (console) from service accounts (programmatic)',
                    compliance_impact='Violates separation of duties principle'
                )
        except ClientError as e:
            print(f"Warning: Could not check access patterns for user {user_name}: {e}")

    def scan_iam_roles(self):
        """Scan IAM roles for security issues"""
        print("🔍 Scanning IAM Roles for vulnerabilities...")
        
        try:
            roles = self.iam.list_roles()['Roles']
            
            for role in roles:
                # Skip AWS managed roles
                if role['RoleName'].startswith('aws-'):
                    continue
                
                role_name = role['RoleName']
                
                # Check trust policies
                self._check_role_trust_policy(role, role_name)
                
                # Check for unused roles
                self._check_unused_roles(role, role_name)
                
        except ClientError as e:
            print(f"❌ Error scanning IAM roles: {e}")

    def _check_role_trust_policy(self, role, role_name):
        """Check role trust policies for security issues"""
        trust_policy = role['AssumeRolePolicyDocument']
        
        for stmt in trust_policy.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                principal = stmt.get('Principal', {})
                
                # Check for wildcard principals
                if principal == '*' or (isinstance(principal, dict) and '*' in principal.values()):
                    self.add_finding(
                        severity='CRITICAL',
                        category='Access Control',
                        title='Role Assumable by Anyone',
                        description=f'Role {role_name} can be assumed by any AWS principal (*)',
                        resource_id=role_name,
                        resource_type='IAMRole',
                        recommendation='Restrict role assumption to specific trusted principals',
                        compliance_impact='Critical security violation - anyone can assume this role'
                    )
                
                # Check for cross-account access without conditions
                if isinstance(principal, dict):
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if ':root' in aws_principal and 'Condition' not in stmt:
                            # Extract account ID
                            account_id = aws_principal.split(':')[4] if ':' in aws_principal else 'Unknown'
                            
                            # Check if it's external account
                            try:
                                current_account = self.sts.get_caller_identity()['Account']
                                if account_id != current_account and account_id != 'Unknown':
                                    self.add_finding(
                                        severity='HIGH',
                                        category='Access Control',
                                        title='Cross-Account Role Without Conditions',
                                        description=f'Role {role_name} allows cross-account access from {account_id} without conditions',
                                        resource_id=role_name,
                                        resource_type='IAMRole',
                                        recommendation='Add conditions to limit cross-account access (e.g., ExternalId, MFA)',
                                        compliance_impact='Potential unauthorized cross-account access'
                                    )
                            except ClientError:
                                pass

    def _check_unused_roles(self, role, role_name):
        """Check for unused IAM roles"""
        # Check last used information
        last_used = role.get('RoleLastUsed', {})
        if 'LastUsedDate' in last_used:
            days_since_used = (datetime.now(timezone.utc).replace(tzinfo=None) - last_used['LastUsedDate'].replace(tzinfo=None)).days
            
            if days_since_used > 90:  # Not used in 90 days
                self.add_finding(
                    severity='LOW',
                    category='Resource Management',
                    title='Unused IAM Role',
                    description=f'Role {role_name} has not been used for {days_since_used} days',
                    resource_id=role_name,
                    resource_type='IAMRole',
                    recommendation='Review and remove unused roles to reduce attack surface',
                    compliance_impact='Unused roles increase security complexity'
                )
        else:
            # Role has never been used
            role_age = (datetime.now(timezone.utc).replace(tzinfo=None) - role['CreateDate'].replace(tzinfo=None)).days
            if role_age > 30:  # Created more than 30 days ago but never used
                self.add_finding(
                    severity='LOW',
                    category='Resource Management',
                    title='Never Used IAM Role',
                    description=f'Role {role_name} was created {role_age} days ago but has never been used',
                    resource_id=role_name,
                    resource_type='IAMRole',
                    recommendation='Review necessity and remove if not needed',
                    compliance_impact='Unused roles increase security complexity'
                )

    def check_password_policy(self):
        """Check account password policy"""
        print("🔍 Checking Password Policy...")
        
        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            
            # Check minimum password length
            min_length = policy.get('MinimumPasswordLength', 0)
            if min_length < 14:
                self.add_finding(
                    severity='MEDIUM',
                    category='Authentication',
                    title='Weak Password Length Requirement',
                    description=f'Password policy requires minimum length of {min_length} characters (recommended: 14+)',
                    resource_id='AccountPasswordPolicy',
                    resource_type='PasswordPolicy',
                    recommendation='Set minimum password length to 14 characters or more',
                    compliance_impact='Violates CIS AWS Benchmark 1.5'
                )
            
            # Check for required character types
            required_checks = {
                'RequireUppercaseCharacters': 'uppercase letters',
                'RequireLowercaseCharacters': 'lowercase letters', 
                'RequireNumbers': 'numbers',
                'RequireSymbols': 'special characters'
            }
            
            for check, description in required_checks.items():
                if not policy.get(check, False):
                    self.add_finding(
                        severity='MEDIUM',
                        category='Authentication',
                        title=f'Password Policy Missing {description.title()}',
                        description=f'Password policy does not require {description}',
                        resource_id='AccountPasswordPolicy',
                        resource_type='PasswordPolicy',
                        recommendation=f'Enable requirement for {description} in passwords',
                        compliance_impact='Weakens password strength requirements'
                    )
            
            # Check password reuse prevention
            if not policy.get('PasswordReusePrevention', 0) >= 24:
                self.add_finding(
                    severity='LOW',
                    category='Authentication',
                    title='Insufficient Password Reuse Prevention',
                    description=f'Password policy prevents reuse of only {policy.get("PasswordReusePrevention", 0)} previous passwords',
                    resource_id='AccountPasswordPolicy',
                    resource_type='PasswordPolicy',
                    recommendation='Prevent reuse of at least 24 previous passwords',
                    compliance_impact='Users may reuse recent passwords'
                )
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                self.add_finding(
                    severity='HIGH',
                    category='Authentication',
                    title='No Password Policy Configured',
                    description='Account has no password policy configured',
                    resource_id='AccountPasswordPolicy',
                    resource_type='PasswordPolicy',
                    recommendation='Configure a strong password policy for the account',
                    compliance_impact='Violates CIS AWS Benchmark 1.5-1.11'
                )

    def generate_security_score(self):
        """Generate overall security score"""
        total_issues = self.results['total_issues']
        critical = self.results['critical_issues']
        high = self.results['high_issues']
        medium = self.results['medium_issues']
        low = self.results['low_issues']
        
        # Calculate weighted score (100 = perfect, 0 = very bad)
        if total_issues == 0:
            score = 100
        else:
            # Weight: Critical=15, High=8, Medium=3, Low=1
            weighted_issues = (critical * 15) + (high * 8) + (medium * 3) + (low * 1)
            score = max(0, 100 - min(100, weighted_issues * 1.5))
        
        risk_level = 'LOW'
        if score < 30:
            risk_level = 'CRITICAL'
        elif score < 50:
            risk_level = 'HIGH'
        elif score < 70:
            risk_level = 'MEDIUM'
        
        self.results['security_score'] = score
        self.results['risk_level'] = risk_level
        
        return score, risk_level

    def run_comprehensive_scan(self):
        """Run complete IAM security scan"""
        print("🚀 Starting Comprehensive IAM Security Scan...")
        print("=" * 50)
        
        # Run all scans
        self.scan_iam_policies()
        self.scan_iam_users()
        self.scan_iam_roles()
        self.check_password_policy()
        
        # Generate security score
        score, risk_level = self.generate_security_score()
        
        # Save results
        script_dir = os.path.dirname(os.path.abspath(__file__))
        results_dir = os.path.join(script_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        
        with open(os.path.join(results_dir, "iam_scan_report.json"), "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 IAM SECURITY SCAN SUMMARY")
        print("=" * 50)
        print(f"🔍 Total Issues Found: {self.results['total_issues']}")
        print(f"🚨 Critical: {self.results['critical_issues']}")
        print(f"⚠️  High: {self.results['high_issues']}")
        print(f"📋 Medium: {self.results['medium_issues']}")
        print(f"ℹ️  Low: {self.results['low_issues']}")
        print(f"📊 Security Score: {score}/100")
        print(f"🎯 Risk Level: {risk_level}")
        print(f"✅ Report saved to: scan/results/iam_scan_report.json")
        print("=" * 50)
        
        return self.results

# Legacy function for backward compatibility
def scan_iam_permissions():
    """Legacy function - use IAMSecurityScanner.run_comprehensive_scan() instead"""
    scanner = IAMSecurityScanner()
    return scanner.run_comprehensive_scan()

if __name__ == "__main__":
    scanner = IAMSecurityScanner()
    results = scanner.run_comprehensive_scan()
