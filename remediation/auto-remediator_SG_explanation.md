# Auto-Remediator Security Group: Block-by-Block Explanation

Since you wanted to use an open-source/standard integration for email instead of Teams, we are using **Amazon SNS (Simple Notification Service)**. SNS is the standard, built-in way to send emails in AWS securely without hardcoding Gmail passwords.

We split this solution into two files:
1. `auto-remediator_SG.py` (The detector)
2. `lambda_remediator.py` (The fixer & notifier)

Let's break down how they work!

---

## 1. The Detector (`auto-remediator_SG.py`)

This is the script you can run on a schedule to hunt for bad security rules.

### Setup and Connection
```python
ec2 = boto3.client('ec2', region_name=region)
lambda_client = boto3.client('lambda', region_name=region)
```
Just like your previous script, we first introduce ourselves to AWS. We create two clients here: one for `ec2` (to check the security groups) and one for `lambda` (to trigger the fix).

### Finding the Target Instances
```python
instances_response = ec2.describe_instances(
    Filters=[
        {'Name': 'tag:Environment', 'Values': ['*prod*', '*Prod*']},
        {'Name': 'instance-state-name', 'Values': ['running']}
    ]
)
```
We don't want to scan everything—only production servers. We use `Filters` to ask AWS to only return running instances that have a tag called `Environment` containing the word `prod`.

### Hunting the Bad Rules
```python
management_ports = [22, 3389] # SSH and RDP
# ... (inside the loop)
if from_port in management_ports or to_port in management_ports:
    for ip_range in permission.get('IpRanges', []):
        if ip_range.get('CidrIp') == '0.0.0.0/0':
```
This is the core logic. We loop through all the Security Groups attached to those production instances. 
1. We check if the rule is for port `22` (SSH - Linux) or `3389` (RDP - Windows). 
2. If it is, we check if the allowed IP address is `0.0.0.0/0`. In networking, `0.0.0.0/0` means "the entire internet".
If both are true, we have a security violation!

### Pulling the Trigger
```python
payload = {
    "security_group_id": sg_id,
    "risky_permissions": risky_permissions
}
response = lambda_client.invoke(
    FunctionName=lambda_function_name,
    InvocationType='Event',
    Payload=json.dumps(payload)
)
```
Instead of the script trying to fix it directly, it bundles up the bad Security Group ID and the exact bad rule into a `payload` (a tiny JSON package) and throws it over the fence to AWS Lambda. `InvocationType='Event'` means "fire and forget"—the script triggers Lambda and immediately moves on without waiting.

---

## 2. The Fixer (`lambda_remediator.py`)

This code lives inside AWS Lambda. It wakes up when the detector throws a payload at it.

### Receiving the Package
```python
def lambda_handler(event, context):
    sg_id = event.get('security_group_id')
    risky_permissions = event.get('risky_permissions', [])
```
Every Lambda function has a `lambda_handler`. The `event` variable is simply the `payload` that our detector script sent! We unpack the Security Group ID and the risky rules.

### The Auto-Remediation (The Fix)
```python
ec2.revoke_security_group_ingress(
    GroupId=sg_id,
    IpPermissions=risky_permissions
)
```
This is the most powerful line of code. We use the EC2 client's `revoke_security_group_ingress` method to permanently delete the bad rules from the Security Group. 

### The Notification (The Email via SNS)
```python
sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
sns.publish(
    TopicArn=sns_topic_arn,
    Subject="Security Alert: Auto-Remediation Triggered",
    Message=message
)
```
Instead of writing 30 lines of code to log into Gmail, we use Amazon SNS. 
1. We read the `SNS_TOPIC_ARN` (the ID of your notification channel) from the Lambda's environment variables.
2. We use `sns.publish` to shout our message into that channel.
3. Because you would subscribe your email address to that SNS Topic in the AWS Console, AWS handles delivering the beautifully formatted email to your inbox instantly.
