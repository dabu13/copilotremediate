import boto3

def start_stopped_instances(region='ap-south-1'):
    # Initialize the EC2 client
    ec2 = boto3.client('ec2', region_name=region)
    
    # Find all stopped instances
    print(f"Searching for stopped instances in {region}...")
    response = ec2.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
    )
    
    # Extract Instance IDs from the JSON-like response
    stopped_instance_ids = []
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            stopped_instance_ids.append(instance['InstanceId'])
            
    # Start the instances if we found any
    if not stopped_instance_ids:
        print("No stopped instances found. Nothing to do!")
        return

    print(f"Found {len(stopped_instance_ids)} stopped instance(s): {stopped_instance_ids}")
    print("Starting them now...")
    
    # Issue the start command
    start_response = ec2.start_instances(InstanceIds=stopped_instance_ids)
    
    # Print a clean summary of what happened
    for instance in start_response.get('StartingInstances', []):
        print(f" -> Instance {instance['InstanceId']} state changing to: {instance['CurrentState']['Name']}")

    # Wait for instances to reach 'running' state
    print("\nWaiting for instances to enter 'running' state...")
    waiter_running = ec2.get_waiter('instance_running')
    waiter_running.wait(InstanceIds=stopped_instance_ids)
    
    # Wait for status checks to pass (heartbeat)
    print("Waiting for instance status checks to pass (this may take a few minutes)...")
    waiter_status = ec2.get_waiter('instance_status_ok')
    waiter_status.wait(InstanceIds=stopped_instance_ids)
    print("All status checks passed! Instances are fully ready.")

if __name__ == "__main__":
    start_stopped_instances()
