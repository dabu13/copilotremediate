import boto3
import json

def detect_and_remediate(region='ap-south-1', lambda_function_name='arn:aws:lambda:ap-south-1:123456789012:function:SGremediator'):
    """
    Scans for production EC2 instances, checks their Security Groups for open 
    management ports (22, 3389) from the internet (0.0.0.0/0), and triggers a 
    Lambda function to remediate if found.
    """
    ec2 = boto3.client('ec2', region_name=region)
    lambda_client = boto3.client('lambda', region_name=region)
    
    # 1. Find all EC2 instances tagged with "Production" (case-insensitive via wildcard)
    print("Scanning for Production EC2 instances...")
    instances_response = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:environment', 'Values': ['production', 'Production', '*prod*', '*Prod*']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )
    
    # Extract unique Security Group IDs attached to these production instances
    prod_sg_ids = set()
    for reservation in instances_response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            for sg in instance.get('SecurityGroups', []):
                prod_sg_ids.add(sg['GroupId'])
                
    if not prod_sg_ids:
        print("No production instances found or they have no Security Groups attached. Exiting.")
        return

    # 2. Inspect the Security Groups for risky rules
    print(f"Found {len(prod_sg_ids)} Security Group(s) attached to Production instances. Inspecting rules...")
    sg_response = ec2.describe_security_groups(GroupIds=list(prod_sg_ids))
    
    management_ports = [22, 3389] # SSH and RDP
    
    for sg in sg_response.get('SecurityGroups', []):
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        risky_permissions = []
        
        # Look through all inbound (Ingress) rules
        for permission in sg.get('IpPermissions', []):
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            
            # Check if this rule applies to our management ports
            if from_port in management_ports or to_port in management_ports:
                # Check if it allows access from anywhere (0.0.0.0/0)
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        print(f"[WARNING] Risky rule found in SG '{sg_name}' ({sg_id}): Port {from_port} open to the internet!")
                        # We keep track of the exact permission object to pass to Lambda
                        risky_permissions.append(permission)
                        
        # 3. Trigger the Auto-Remediation Lambda for this Security Group
        if risky_permissions:
            print(f"Triggering Auto-Remediation Lambda for Security Group: {sg_id}...")
            payload = {
                "security_group_id": sg_id,
                "risky_permissions": risky_permissions
            }
            
            try:
                response = lambda_client.invoke(
                    FunctionName=lambda_function_name,
                    InvocationType='Event', # 'Event' means asynchronous (fire and forget)
                    Payload=json.dumps(payload)
                )
                print(f" -> Lambda triggered successfully! Status Code: {response['StatusCode']}")
            except Exception as e:
                print(f" -> Failed to trigger Lambda: {e}")
        else:
            print(f"Security Group '{sg_name}' ({sg_id}) is secure.")

if __name__ == "__main__":
    detect_and_remediate()
