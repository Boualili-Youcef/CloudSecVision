import boto3

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
        print(f"Error : {bucket_name}: {e}")
        return False

def main():
    print("Script started")
    buckets = list_buckets()
    print(f"🌐 Buckets detected : {len(buckets)}")
    for bucket in buckets:
        if check_bucket_public(bucket):
            print(f"🚨 Public bucket found : {bucket}")
        else:
            print(f"✅ Private bucket : {bucket}")
    
if __name__ == "__main__":
    main()
