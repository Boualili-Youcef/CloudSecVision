import boto3
import json

def scan_ec2_security_groups():
    ec2 = boto3.client('ec2')
    results = []

    security_groups = ec2.describe_security_groups()['SecurityGroups']

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', '')

        for permission in sg.get('IpPermissions', []):
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_protocol = permission.get('IpProtocol')

            if from_port == 22 and to_port == 22 and (ip_protocol == 'tcp' or ip_protocol == '-1'):
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr == '0.0.0.0/0':
                        results.append({
                            'GroupId': sg_id,
                            'GroupName': sg_name,
                            'Port': 22,
                            'IpRange': cidr,
                            'Issue': 'SSH port 22 open to the world'
                        })
                for ipv6_range in permission.get('Ipv6Ranges', []):
                    cidr_ipv6 = ipv6_range.get('CidrIpv6')
                    if cidr_ipv6 == '::/0':
                        results.append({
                            'GroupId': sg_id,
                            'GroupName': sg_name,
                            'Port': 22,
                            'IpRange': cidr_ipv6,
                            'Issue': 'SSH port 22 open to the world (IPv6)'
                        })

    with open("scan/results/ec2_scan.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"✅ EC2 report generated at scan/results/ec2_scan.json ({len(results)} issues found)")
    
    return results

if __name__ == "__main__":
    scan_ec2_security_groups()
