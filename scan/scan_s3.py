import boto3
import json
import os

def list_buckets():
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    return [bucket['Name'] for bucket in response['Buckets']]

def check_bucket_public(bucket_name):
    s3 = boto3.client('s3')
    
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if 'AllUsers' in grant['Grantee'].get('URI', ''):
                return True
        return False
    except Exception as e:
        print(f"Error checking {bucket_name}: {e}")
        return False

def main():
    print("Script started")
    results = []
    
    buckets = list_buckets()
    print(f"🌐 Buckets detected: {len(buckets)}")
    
    for bucket in buckets:
        if check_bucket_public(bucket):
            results.append({
                'BucketName': bucket,
                'Issue': 'Bucket is publicly accessible'
            })
            print(f"🚨 Public bucket found: {bucket}")
        else:
            print(f"✅ Private bucket: {bucket}")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    
    output_path = os.path.join(results_dir, "s3_scan_report.json")
    
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ S3 report generated at {output_path} ({len(results)} issues found)")

if __name__ == "__main__":
    main()