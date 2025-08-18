import boto3
import json
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import logging

class EC2SecurityScanner:
    def __init__(self):
        self.ec2 = boto3.client('ec2')
        self.ssm = boto3.client('ssm')
        self.elbv2 = boto3.client('elbv2')
        self.elb = boto3.client('elb')
        self.results = {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'findings': []
        }
        
        # Critical ports and their descriptions
        self.CRITICAL_PORTS = {
            22: {'name': 'SSH', 'risk': 'CRITICAL'},
            3389: {'name': 'RDP', 'risk': 'CRITICAL'},
            21: {'name': 'FTP', 'risk': 'HIGH'},
            23: {'name': 'Telnet', 'risk': 'CRITICAL'},
            135: {'name': 'RPC', 'risk': 'HIGH'},
            139: {'name': 'NetBIOS', 'risk': 'HIGH'},
            445: {'name': 'SMB', 'risk': 'HIGH'},
            1433: {'name': 'MSSQL', 'risk': 'HIGH'},
            3306: {'name': 'MySQL', 'risk': 'HIGH'},
            5432: {'name': 'PostgreSQL', 'risk': 'HIGH'},
            6379: {'name': 'Redis', 'risk': 'HIGH'},
            27017: {'name': 'MongoDB', 'risk': 'HIGH'},
            11211: {'name': 'Memcached', 'risk': 'MEDIUM'},
            9200: {'name': 'Elasticsearch', 'risk': 'HIGH'},
            8080: {'name': 'HTTP-Alt', 'risk': 'MEDIUM'},
            8443: {'name': 'HTTPS-Alt', 'risk': 'MEDIUM'}
        }

    def add_finding(self, severity, category, title, description, resource_id, resource_type='SecurityGroup', recommendation='', compliance_impact=''):
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
            'timestamp': datetime.utcnow().isoformat()
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

    def scan_security_groups(self):
        """Comprehensive security group vulnerability scan"""
        print("🔍 Scanning Security Groups for vulnerabilities...")
        
        try:
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'N/A')
                
                # Check for dangerous inbound rules
                self._check_dangerous_inbound_rules(sg, sg_id, sg_name)
                
                # Check for overly permissive outbound rules
                self._check_outbound_rules(sg, sg_id, sg_name)
                
                # Check for unused security groups
                self._check_unused_security_groups(sg, sg_id, sg_name)
                
                # Check for default security groups
                self._check_default_security_groups(sg, sg_id, sg_name)
                
        except ClientError as e:
            print(f"❌ Error scanning security groups: {e}")

    def _check_dangerous_inbound_rules(self, sg, sg_id, sg_name):
        """Check for dangerous inbound rules"""
        for permission in sg.get('IpPermissions', []):
            from_port = permission.get('FromPort', 0)
            to_port = permission.get('ToPort', 65535)
            ip_protocol = permission.get('IpProtocol', '')
            
            # Check each IP range
            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                self._analyze_rule(sg_id, sg_name, from_port, to_port, ip_protocol, cidr, 'IPv4')
                
            # Check IPv6 ranges
            for ipv6_range in permission.get('Ipv6Ranges', []):
                cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
                self._analyze_rule(sg_id, sg_name, from_port, to_port, ip_protocol, cidr_ipv6, 'IPv6')

    def _analyze_rule(self, sg_id, sg_name, from_port, to_port, protocol, cidr, ip_version):
        """Analyze individual security group rule - checks ALL applicable vulnerabilities"""
        is_public = cidr in ['0.0.0.0/0', '::/0']
        
        if not is_public:
            return
        
        # Check for all traffic open (MOST CRITICAL - check first)
        if protocol == '-1' or (from_port == 0 and to_port == 65535):
            self.add_finding(
                severity='CRITICAL',
                category='Network Security',
                title='All Traffic Open to Internet',
                description=f'Security group {sg_name} ({sg_id}) allows ALL traffic from anywhere ({cidr})',
                resource_id=sg_id,
                recommendation='Remove this rule and add specific rules for required ports only',
                compliance_impact='Major security violation - immediate remediation required'
            )
        
        # Check for critical ports open to public (independent check)
        if from_port == to_port and from_port in self.CRITICAL_PORTS:
            port_info = self.CRITICAL_PORTS[from_port]
            self.add_finding(
                severity=port_info['risk'],
                category='Network Security',
                title=f'{port_info["name"]} Port Open to Internet',
                description=f'Security group {sg_name} ({sg_id}) has {port_info["name"]} port {from_port} open to the entire internet ({cidr})',
                resource_id=sg_id,
                recommendation=f'Restrict {port_info["name"]} access to specific IP ranges or use VPN/bastion host',
                compliance_impact='Violates CIS AWS Foundations Benchmark 4.1-4.2'
            )
        
        # Check for wide port ranges (independent check - but skip if already flagged as "all traffic")
        if (to_port - from_port > 100) and not (protocol == '-1' or (from_port == 0 and to_port == 65535)):
            self.add_finding(
                severity='HIGH',
                category='Network Security', 
                title='Wide Port Range Open to Internet',
                description=f'Security group {sg_name} ({sg_id}) has wide port range {from_port}-{to_port} open to internet ({cidr})',
                resource_id=sg_id,
                recommendation='Restrict to specific ports needed for your application',
                compliance_impact='Increases attack surface significantly'
            )

    def _check_outbound_rules(self, sg, sg_id, sg_name):
        """Check for overly permissive outbound rules"""
        for permission in sg.get('IpPermissionsEgress', []):
            protocol = permission.get('IpProtocol', '')
            from_port = permission.get('FromPort', 0)
            to_port = permission.get('ToPort', 65535)
            
            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr == '0.0.0.0/0' and protocol == '-1':
                    self.add_finding(
                        severity='MEDIUM',
                        category='Network Security',
                        title='Unrestricted Outbound Traffic',
                        description=f'Security group {sg_name} ({sg_id}) allows all outbound traffic to anywhere',
                        resource_id=sg_id,
                        recommendation='Implement least privilege by restricting outbound traffic to required destinations',
                        compliance_impact='May allow data exfiltration'
                    )

    def _check_unused_security_groups(self, sg, sg_id, sg_name):
        """Check for unused security groups"""
        try:
            # Check if security group is attached to any instances
            instances = self.ec2.describe_instances(
                Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
            )
            
            # Check if attached to any network interfaces
            enis = self.ec2.describe_network_interfaces(
                Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
            )
            
            has_instances = any(instances['Reservations'])
            has_enis = any(enis['NetworkInterfaces'])
            
            if not has_instances and not has_enis and sg_name != 'default':
                self.add_finding(
                    severity='LOW',
                    category='Resource Management',
                    title='Unused Security Group',
                    description=f'Security group {sg_name} ({sg_id}) is not attached to any resources',
                    resource_id=sg_id,
                    recommendation='Remove unused security groups to reduce management overhead',
                    compliance_impact='Increases complexity and potential misconfigurations'
                )
                
        except ClientError as e:
            print(f"Warning: Could not check usage for SG {sg_id}: {e}")

    def _check_default_security_groups(self, sg, sg_id, sg_name):
        """Check for modifications to default security groups"""
        if sg_name == 'default':
            # Default SG should not have inbound rules
            if sg.get('IpPermissions'):
                self.add_finding(
                    severity='HIGH',
                    category='Configuration Management',
                    title='Default Security Group Modified',
                    description=f'Default security group {sg_id} has custom inbound rules',
                    resource_id=sg_id,
                    recommendation='Do not modify default security groups. Create custom security groups instead',
                    compliance_impact='Violates AWS security best practices'
                )

    def scan_ec2_instances(self):
        """Scan EC2 instances for security issues"""
        print("🔍 Scanning EC2 Instances for vulnerabilities...")
        
        try:
            reservations = self.ec2.describe_instances()['Reservations']
            
            for reservation in reservations:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                        
                    instance_id = instance['InstanceId']
                    
                    # Check for public instances
                    self._check_public_instances(instance, instance_id)
                    
                    # Check for unencrypted EBS volumes
                    self._check_ebs_encryption(instance, instance_id)
                    
                    # Check for IMDSv1 usage (security vulnerability)
                    self._check_instance_metadata_service(instance, instance_id)
                    
                    # Check for detailed monitoring
                    self._check_detailed_monitoring(instance, instance_id)
                    
                    # Check for old AMIs
                    self._check_ami_age(instance, instance_id)
                    
        except ClientError as e:
            print(f"❌ Error scanning EC2 instances: {e}")

    def _check_public_instances(self, instance, instance_id):
        """Check for instances with public IP addresses"""
        public_ip = instance.get('PublicIpAddress')
        if public_ip:
            self.add_finding(
                severity='HIGH',
                category='Network Security',
                title='EC2 Instance Has Public IP',
                description=f'Instance {instance_id} has a public IP address ({public_ip})',
                resource_id=instance_id,
                resource_type='EC2Instance',
                recommendation='Use NAT Gateway/Instance for outbound internet access and Application Load Balancer for inbound',
                compliance_impact='Increases attack surface and potential for unauthorized access'
            )

    def _check_ebs_encryption(self, instance, instance_id):
        """Check for unencrypted EBS volumes"""
        for bdm in instance.get('BlockDeviceMappings', []):
            if 'Ebs' in bdm:
                volume_id = bdm['Ebs']['VolumeId']
                try:
                    volume = self.ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
                    if not volume.get('Encrypted', False):
                        self.add_finding(
                            severity='HIGH',
                            category='Data Protection',
                            title='Unencrypted EBS Volume',
                            description=f'EBS volume {volume_id} attached to instance {instance_id} is not encrypted',
                            resource_id=volume_id,
                            resource_type='EBSVolume',
                            recommendation='Enable EBS encryption for all volumes to protect data at rest',
                            compliance_impact='Violates data protection regulations (GDPR, HIPAA, PCI-DSS)'
                        )
                except ClientError:
                    pass

    def _check_instance_metadata_service(self, instance, instance_id):
        """Check for IMDSv1 usage (security vulnerability)"""
        metadata_options = instance.get('MetadataOptions', {})
        http_tokens = metadata_options.get('HttpTokens', 'optional')
        
        if http_tokens == 'optional':
            self.add_finding(
                severity='MEDIUM',
                category='Configuration Security',
                title='IMDSv1 Enabled (Security Risk)',
                description=f'Instance {instance_id} allows IMDSv1 which is vulnerable to SSRF attacks',
                resource_id=instance_id,
                resource_type='EC2Instance',
                recommendation='Enforce IMDSv2 by setting HttpTokens to "required"',
                compliance_impact='Vulnerable to Server-Side Request Forgery (SSRF) attacks'
            )

    def _check_detailed_monitoring(self, instance, instance_id):
        """Check if detailed monitoring is enabled"""
        monitoring = instance.get('Monitoring', {}).get('State', 'disabled')
        if monitoring == 'disabled':
            self.add_finding(
                severity='LOW',
                category='Monitoring',
                title='Detailed Monitoring Disabled',
                description=f'Instance {instance_id} does not have detailed monitoring enabled',
                resource_id=instance_id,
                resource_type='EC2Instance',
                recommendation='Enable detailed monitoring for better visibility and faster response to issues',
                compliance_impact='Reduced visibility into system performance and security events'
            )

    def _check_ami_age(self, instance, instance_id):
        """Check for instances using old AMIs"""
        try:
            ami_id = instance['ImageId']
            ami = self.ec2.describe_images(ImageIds=[ami_id])['Images'][0]
            creation_date = datetime.strptime(ami['CreationDate'][:19], '%Y-%m-%dT%H:%M:%S')
            age_days = (datetime.utcnow() - creation_date).days
            
            if age_days > 90:  # AMI older than 90 days
                self.add_finding(
                    severity='MEDIUM',
                    category='Patch Management',
                    title='Instance Using Old AMI',
                    description=f'Instance {instance_id} is using AMI {ami_id} that is {age_days} days old',
                    resource_id=instance_id,
                    resource_type='EC2Instance',
                    recommendation='Update to latest AMI with security patches and consider automated patching',
                    compliance_impact='May contain unpatched security vulnerabilities'
                )
        except (ClientError, KeyError):
            pass

    def scan_load_balancers(self):
        """Scan load balancers for security issues"""
        print("🔍 Scanning Load Balancers for vulnerabilities...")
        
        # Scan Application Load Balancers
        try:
            albs = self.elbv2.describe_load_balancers()['LoadBalancers']
            for alb in albs:
                if alb['Type'] == 'application':
                    self._check_alb_security(alb)
        except ClientError as e:
            print(f"Warning: Could not scan ALBs: {e}")
        
        # Scan Classic Load Balancers
        try:
            clbs = self.elb.describe_load_balancers()['LoadBalancerDescriptions']
            for clb in clbs:
                self._check_clb_security(clb)
        except ClientError as e:
            print(f"Warning: Could not scan CLBs: {e}")

    def _check_alb_security(self, alb):
        """Check Application Load Balancer security"""
        lb_arn = alb['LoadBalancerArn']
        lb_name = alb['LoadBalancerName']
        
        # Check for internet-facing load balancers
        if alb['Scheme'] == 'internet-facing':
            try:
                listeners = self.elbv2.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
                for listener in listeners:
                    if listener['Protocol'] == 'HTTP':
                        self.add_finding(
                            severity='HIGH',
                            category='Data Protection',
                            title='Load Balancer Using HTTP',
                            description=f'Internet-facing ALB {lb_name} has HTTP listener (port {listener["Port"]})',
                            resource_id=lb_arn,
                            resource_type='LoadBalancer',
                            recommendation='Use HTTPS only and redirect HTTP to HTTPS',
                            compliance_impact='Data transmitted in plaintext, violates security standards'
                        )
            except ClientError:
                pass

    def _check_clb_security(self, clb):
        """Check Classic Load Balancer security"""
        lb_name = clb['LoadBalancerName']
        
        if clb['Scheme'] == 'internet-facing':
            for listener in clb['ListenerDescriptions']:
                listener_desc = listener['Listener']
                if listener_desc['Protocol'] == 'HTTP':
                    self.add_finding(
                        severity='HIGH',
                        category='Data Protection',
                        title='Classic Load Balancer Using HTTP',
                        description=f'Internet-facing CLB {lb_name} has HTTP listener (port {listener_desc["LoadBalancerPort"]})',
                        resource_id=lb_name,
                        resource_type='LoadBalancer',
                        recommendation='Migrate to ALB with HTTPS or configure SSL certificate',
                        compliance_impact='Data transmitted in plaintext'
                    )

    def check_vpc_flow_logs(self):
        """Check if VPC Flow Logs are enabled"""
        print("🔍 Checking VPC Flow Logs...")
        
        try:
            vpcs = self.ec2.describe_vpcs()['Vpcs']
            flow_logs = self.ec2.describe_flow_logs()['FlowLogs']
            
            # Get VPCs with flow logs enabled
            vpcs_with_flow_logs = {fl['ResourceId'] for fl in flow_logs if fl['ResourceType'] == 'VPC'}
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                if vpc_id not in vpcs_with_flow_logs:
                    self.add_finding(
                        severity='MEDIUM',
                        category='Logging & Monitoring',
                        title='VPC Flow Logs Disabled',
                        description=f'VPC {vpc_id} does not have flow logs enabled',
                        resource_id=vpc_id,
                        resource_type='VPC',
                        recommendation='Enable VPC Flow Logs for network traffic monitoring and security analysis',
                        compliance_impact='Reduced visibility into network traffic for security monitoring'
                    )
                    
        except ClientError as e:
            print(f"Warning: Could not check VPC flow logs: {e}")

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
            # Weight: Critical=10, High=5, Medium=2, Low=1
            weighted_issues = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
            score = max(0, 100 - min(100, weighted_issues * 2))
        
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
        """Run complete EC2 security scan"""
        print("🚀 Starting Comprehensive EC2 Security Scan...")
        print("=" * 50)
        
        # Run all scans
        self.scan_security_groups()
        self.scan_ec2_instances()
        self.scan_load_balancers()
        self.check_vpc_flow_logs()
        
        # Generate security score
        score, risk_level = self.generate_security_score()
        
        # Save results
        with open("scan/results/ec2_scan.json", "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 EC2 SECURITY SCAN SUMMARY")
        print("=" * 50)
        print(f"🔍 Total Issues Found: {self.results['total_issues']}")
        print(f"🚨 Critical: {self.results['critical_issues']}")
        print(f"⚠️  High: {self.results['high_issues']}")
        print(f"📋 Medium: {self.results['medium_issues']}")
        print(f"ℹ️  Low: {self.results['low_issues']}")
        print(f"📊 Security Score: {score}/100")
        print(f"🎯 Risk Level: {risk_level}")
        print(f"✅ Report saved to: scan/results/ec2_scan.json")
        print("=" * 50)
        
        return self.results

# Legacy function for backward compatibility
def scan_ec2_security_groups():
    """Legacy function - use EC2SecurityScanner.run_comprehensive_scan() instead"""
    scanner = EC2SecurityScanner()
    return scanner.run_comprehensive_scan()

if __name__ == "__main__":
    scanner = EC2SecurityScanner()
    results = scanner.run_comprehensive_scan()
