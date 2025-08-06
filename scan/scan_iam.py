import os
import boto3
import json

def is_policy_too_permissive(policy_doc):
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') == 'Allow':
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions or "*" in resources:
                return True
    return False

def scan_iam_permissions():
    iam = boto3.client('iam')
    results = []

    policies = iam.list_policies(Scope='Local', OnlyAttached=True)['Policies'] # Only attached policies 
    for policy in policies:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        policy_doc = policy_version['PolicyVersion']['Document']

        if is_policy_too_permissive(policy_doc):
            results.append({
                'PolicyName': policy_name,
                'Arn': policy_arn,
                'Issue': 'Too permissive ("*" in Action or Resource)'
            })

    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results")

    os.makedirs(results_dir, exist_ok=True)

    output_path = os.path.join(results_dir, "iam_scan_report.json")

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"✅ IAM report generated at {output_path} ({len(results)} issues found)")

if __name__ == "__main__":
    scan_iam_permissions()
