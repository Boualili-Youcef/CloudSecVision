import boto3
import json

ec2 = boto3.client('ec2')
response = ec2.describe_security_groups()['SecurityGroups']

print(json.dumps(response, indent=2))