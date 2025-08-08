import boto3
import json
import os
from botocore.exceptions import ClientError

class S3SecurityScanner:
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.results = []
    
    def list_buckets(self):
        """List all S3 buckets in the account"""
        try:
            response = self.s3.list_buckets()
            return [bucket['Name'] for bucket in response['Buckets']]
        except Exception as e:
            print(f"Error listing buckets: {e}")
            return []
    
    def check_bucket_public_access(self, bucket_name):
        """Public access checks for a bucket"""
        
        # A list to store issues found in the bucket
        issues = []
        
        # 1. Check Block Public Access Settings
        try:
            block_config = self.s3.get_public_access_block(Bucket=bucket_name)
            config = block_config['PublicAccessBlockConfiguration']
            
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False), 
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': 'Block Public Access not fully configured',
                    'Severity': 'HIGH',
                    'Details': config
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': 'No Block Public Access configuration found',
                    'Severity': 'CRITICAL',
                    'Recommendation': 'Enable Block Public Access settings'
                })
        
        # 2. Public ACLs and Bucket Policy Checks
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                
                # Check AllUsers
                if 'AllUsers' in grantee.get('URI', ''):
                    issues.append({
                        'BucketName': bucket_name,
                        'Issue': f'Bucket ACL grants {grant["Permission"]} to AllUsers',
                        'Severity': 'CRITICAL',
                        'Permission': grant['Permission']
                    })
                
                # Check AuthenticatedUsers
                if 'AuthenticatedUsers' in grantee.get('URI', ''):
                    issues.append({
                        'BucketName': bucket_name,
                        'Issue': f'Bucket ACL grants {grant["Permission"]} to AuthenticatedUsers',
                        'Severity': 'HIGH',
                        'Permission': grant['Permission']
                    })
        except ClientError as e:
            issues.append({
                'BucketName': bucket_name,
                'Issue': f'Cannot read bucket ACL: {str(e)}',
                'Severity': 'MEDIUM'
            })
        
        # 3. Bucket policy checks
        try:
            policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
            
            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    
                    # public policy check
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        issues.append({
                            'BucketName': bucket_name,
                            'Issue': 'Bucket policy allows public access (Principal: "*")',
                            'Severity': 'CRITICAL',
                            'Actions': statement.get('Action', []),
                            'Resources': statement.get('Resource', [])
                        })
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': f'Cannot read bucket policy: {str(e)}',
                    'Severity': 'MEDIUM'
                })
        
        return issues
    
    def check_bucket_encryption(self, bucket_name):
        """Vérifier le chiffrement du bucket"""
        issues = []
        
        try:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption['ServerSideEncryptionConfiguration']['Rules']
            
            for rule in rules:
                sse = rule.get('ApplyServerSideEncryptionByDefault', {})
                if sse.get('SSEAlgorithm') not in ['AES256', 'aws:kms']:
                    issues.append({
                        'BucketName': bucket_name,
                        'Issue': f'Weak encryption algorithm: {sse.get("SSEAlgorithm")}',
                        'Severity': 'MEDIUM'
                    })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': 'No server-side encryption configured',
                    'Severity': 'HIGH',
                    'Recommendation': 'Enable S3 default encryption'
                })
        
        return issues
    
    def check_bucket_versioning(self, bucket_name):
        """Vérifier la configuration du versioning"""
        issues = []
        
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            
            if status != 'Enabled':
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': f'Bucket versioning is {status}',
                    'Severity': 'MEDIUM',
                    'Recommendation': 'Enable versioning for data protection'
                })
            
            # Vérifier MFA Delete
            mfa_delete = versioning.get('MfaDelete', 'Disabled')
            if mfa_delete != 'Enabled':
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': 'MFA Delete not enabled',
                    'Severity': 'MEDIUM',
                    'Recommendation': 'Enable MFA Delete for additional protection'
                })
        except ClientError as e:
            issues.append({
                'BucketName': bucket_name,
                'Issue': f'Cannot read versioning configuration: {str(e)}',
                'Severity': 'LOW'
            })
        
        return issues
    
    def check_bucket_logging(self, bucket_name):
        """Vérifier la configuration des logs d'accès"""
        issues = []
        
        try:
            logging = self.s3.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging:
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': 'Access logging not configured',
                    'Severity': 'LOW',
                    'Recommendation': 'Enable S3 access logging for audit trails'
                })
        except ClientError as e:
            issues.append({
                'BucketName': bucket_name,
                'Issue': f'Cannot read logging configuration: {str(e)}',
                'Severity': 'LOW'
            })
        
        return issues
    
    def check_bucket_lifecycle(self, bucket_name):
        """Vérifier les politiques de cycle de vie"""
        issues = []
        
        try:
            lifecycle = self.s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                issues.append({
                    'BucketName': bucket_name,
                    'Issue': 'No lifecycle policy configured',
                    'Severity': 'LOW',
                    'Recommendation': 'Configure lifecycle rules for cost optimization'
                })
        
        return issues
    
    def scan_bucket_comprehensive(self, bucket_name):
        """Scan complet d'un bucket S3"""
        print(f"🔍 Scanning bucket: {bucket_name}")
        
        all_issues = []
        
        # Tous les checks de sécurité
        all_issues.extend(self.check_bucket_public_access(bucket_name))
        all_issues.extend(self.check_bucket_encryption(bucket_name))
        all_issues.extend(self.check_bucket_versioning(bucket_name))
        all_issues.extend(self.check_bucket_logging(bucket_name))
        all_issues.extend(self.check_bucket_lifecycle(bucket_name))
        
        # Statistiques du bucket
        try:
            # Compter les objets (échantillon)
            objects = self.s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
            object_count = objects.get('KeyCount', 0)
            
            if object_count > 0:
                print(f"   📁 Found {object_count}+ objects")
        except ClientError:
            pass
        
        # Afficher les résultats par sévérité
        critical = [i for i in all_issues if i.get('Severity') == 'CRITICAL']
        high = [i for i in all_issues if i.get('Severity') == 'HIGH']
        medium = [i for i in all_issues if i.get('Severity') == 'MEDIUM']
        low = [i for i in all_issues if i.get('Severity') == 'LOW']
        
        if critical:
            print(f"   🚨 {len(critical)} CRITICAL issues")
        if high:
            print(f"   ⚠️  {len(high)} HIGH issues")
        if medium:
            print(f"   🟡 {len(medium)} MEDIUM issues")
        if low:
            print(f"   🔵 {len(low)} LOW issues")
        
        if not all_issues:
            print(f"   ✅ No security issues found")
        
        return all_issues

def main():
    """Fonction principale pour le scan S3 avancé"""
    print("🛡️ CloudSecVision - Advanced S3 Security Scanner")
    print("=" * 50)
    
    scanner = S3SecurityScanner()
    
    # Lister tous les buckets
    buckets = scanner.list_buckets()
    print(f"🌐 Found {len(buckets)} S3 buckets to analyze\n")
    
    if not buckets:
        print("ℹ️  No S3 buckets found in this account")
        return []
    
    all_results = []
    
    # Scanner chaque bucket
    for bucket in buckets:
        bucket_issues = scanner.scan_bucket_comprehensive(bucket)
        all_results.extend(bucket_issues)
        print()  # Ligne vide entre les buckets
    
    # Résumé global
    print("=" * 50)
    print(f"📊 SCAN SUMMARY:")
    print(f"   🏢 Buckets scanned: {len(buckets)}")
    print(f"   ⚠️  Total issues: {len(all_results)}")
    
    if all_results:
        severity_counts = {
            'CRITICAL': len([i for i in all_results if i.get('Severity') == 'CRITICAL']),
            'HIGH': len([i for i in all_results if i.get('Severity') == 'HIGH']),
            'MEDIUM': len([i for i in all_results if i.get('Severity') == 'MEDIUM']),
            'LOW': len([i for i in all_results if i.get('Severity') == 'LOW'])
        }
        
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"   {severity}: {count} issues")
    
    # Sauvegarder les résultats
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    
    output_path = os.path.join(results_dir, "s3_scan_report.json")
    
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    
    print(f"\n✅ Detailed report saved: {output_path}")
    
    return all_results

if __name__ == "__main__":
    main()