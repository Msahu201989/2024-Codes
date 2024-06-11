import json
import boto3
import csv
import io

def lambda_handler(event, context):
    # Initialize boto3 clients
    iam_client = boto3.client('iam')

    # S3 bucket and file details
    bucket_name = 'deletes3ifyousee-ivp'
    file_key = 'iam_roles_policies.csv'

    # Fetch the CSV file from S3
    s3_client = boto3.client('s3')
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    content = response['Body'].read().decode('utf-8')

    # Parse CSV content
    csv_reader = csv.DictReader(io.StringIO(content))

    # Track policy attachment status
    all_policies_attached = True

    # Process each row in the CSV
    for row in csv_reader:
        role_name = row['RoleName']
        policy_name = row['PolicyName']
        policy_type = row['PolicyType'].lower().replace(" ", "_")  # Convert to lowercase and replace spaces

        # Handle empty PolicyDocuments
        policy_document_str = row['PolicyDocument'].strip()
        if not policy_document_str:
            print(f"Policy document for {policy_name} is empty. Skipping...")
            continue

        # Check for valid JSON in PolicyDocument
        try:
            policy_document = json.loads(policy_document_str)
        except json.JSONDecodeError:
            print(f"Invalid JSON in PolicyDocument for {policy_name}. Skipping...")
            continue

        print(f"Processing role: {role_name}")

        # Check if the role exists, and create if it does not
        try:
            iam_client.get_role(RoleName=role_name)
            print(f"Role {role_name} exists")
        except iam_client.exceptions.NoSuchEntityException:
            print(f"Role {role_name} does not exist, creating...")
            assume_role_policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            try:
                iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
                    Description=f'Role created by Lambda for {role_name}'
                )
                print(f"Role {role_name} created successfully")
            except Exception as e:
                print(f"Failed to create role {role_name}: {str(e)}")
                all_policies_attached = False
                continue

        # Attach policies based on policy type
        if policy_type == 'aws_managed':
            policy_arn = f'arn:aws:iam::aws:policy/{policy_name}'
        elif policy_type == 'customer_managed':
            account_id = boto3.client('sts').get_caller_identity()['Account']
            policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
            try:
                # Create the policy if it does not exist
                iam_client.create_policy(
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(policy_document)
                )
                print(f'Customer managed policy {policy_name} created successfully')
            except iam_client.exceptions.EntityAlreadyExistsException:
                print(f'Policy {policy_name} already exists')
        elif policy_type == 'inline':
            # Add inline policy to the role
            try:
                iam_client.put_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(policy_document)
                )
                print(f'Inline policy {policy_name} added to role {role_name}')
            except Exception as e:
                print(f"Failed to add inline policy {policy_name} to role {role_name}: {str(e)}")
                all_policies_attached = False
        else:
            print(f"Invalid policy type: {policy_type}")
            all_policies_attached = False

        # Attach the policy to the role for AWS Managed and Customer Managed policies
        if policy_type in ['aws_managed', 'customer_managed']:
            try:
                iam_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy_arn
                )
                print(f'Policy {policy_name} attached to role {role_name}')
            except iam_client.exceptions.NoSuchEntityException:
                print(f"Role {role_name} does not exist")
                all_policies_attached = False
            except iam_client.exceptions.LimitExceededException:
                print(f"Failed to attach policy {policy_name} to role {role_name}: Limit exceeded")
                all_policies_attached = False
            except Exception as e:
                print(f"Failed to attach policy {policy_name} to role {role_name}: {str(e)}")
                all_policies_attached = False

    # Return the result only if all policies are successfully attached
    if all_policies_attached:
        return {
            'statusCode': 200,
            'body': json.dumps('Roles and policies processed successfully')
        }
    else:
        return {
            'statusCode': 500,
            'body': json.dumps('Failed to process all roles and policies')
        }
