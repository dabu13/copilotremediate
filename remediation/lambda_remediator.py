import boto3
import os

# Initialize clients outside the handler for performance reuse
ec2 = boto3.client('ec2')
sns = boto3.client('sns')

def lambda_handler(event, context):
    """
    Lambda function triggered by the SG detector script.
    It receives the Security Group ID and the risky rules to remove.
    Then, it emails the team via Amazon SNS.
    """
    print(f"Received event: {event}")
    
    sg_id = event.get('security_group_id')
    risky_permissions = event.get('risky_permissions', [])
    
    # We expect an SNS Topic ARN to be passed in as an Environment Variable
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    
    if not sg_id or not risky_permissions:
        print("Missing security_group_id or risky_permissions in payload.")
        return {"statusCode": 400, "body": "Invalid Payload"}

    try:
        # 1. REMEDIATE: Remove the risky rules from the Security Group
        print(f"Attempting to remove rules from {sg_id}...")
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=risky_permissions
        )
        print("Rules successfully removed!")
        
        # 2. NOTIFY: Send an email via SNS
        message = (
            f"✅ AUTO-REMEDIATION SUCCESS\n\n"
            f"Action: Removed high-risk internet access (0.0.0.0/0) to management ports.\n"
            f"Security Group ID: {sg_id}\n"
            f"Rules Removed: {len(risky_permissions)}\n\n"
            f"The environment is secure."
        )
        
        if sns_topic_arn:
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject="Security Alert: Auto-Remediation Triggered",
                Message=message
            )
            print("SNS notification sent successfully.")
        else:
            print("WARNING: SNS_TOPIC_ARN environment variable not set. Email not sent.")
            
        return {"statusCode": 200, "body": "Remediation Successful"}
        
    except Exception as e:
        print(f"ERROR during remediation: {e}")
        
        # Send a Failure Notification
        if sns_topic_arn:
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject="🚨 Auto-Remediation FAILED",
                Message=f"Failed to remove rules from Security Group {sg_id}.\nError: {str(e)}"
            )
            
        return {"statusCode": 500, "body": f"Remediation Failed: {str(e)}"}
