import argparse
from scan.scan_ec2 import scan_ec2_security_groups
from scan.scan_iam import scan_iam_permissions
from scan.scan_s3 import main as scan_s3


def main():
    parser = argparse.ArgumentParser(description='CloudSecVision - AWS Security Scanner')
    parser.add_argument('--service', choices=['ec2', 'iam', 's3', 'all'], default='all')
    
    args = parser.parse_args()

    print("🛡️ CloudSecVision - AWS Security Scanner\n")

    
    results = {}
    if args.service in ['ec2', 'all']:
        print("🔍 Scanning EC2 Security Groups...")
        results['ec2'] = scan_ec2_security_groups()
        print()
    
    if args.service in ['iam', 'all']:
        print("🔍 Scanning IAM Policies...")
        results['iam'] = scan_iam_permissions()
        print()

    if args.service in ['s3', 'all']:
        print("🔍 Scanning S3 Buckets...")
        results['s3'] = scan_s3()
        print()
        
if __name__ == "__main__":
    main()