import boto3
import csv
import json
import io

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    s3_client = boto3.client('s3')
    bucket_name = 'deleteiambucket'
    csv_file_key = 'iam_roles_policies.csv'

    roles = iam_client.list_roles()
    output = io.StringIO()
    csv_writer = csv.writer(output)
    csv_writer.writerow(['RoleName', 'PolicyName', 'PolicyType', 'PolicyDocument'])

    for role in roles['Roles']:
        role_name = role['RoleName']
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        inline_policies = iam_client.list_role_policies(RoleName=role_name)

        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            policy_name = policy['PolicyName']
            policy_type = 'AWS Managed' if policy_arn.startswith('arn:aws:iam::aws:policy') else 'Customer Managed'

            if policy_type == 'Customer Managed':
                policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                csv_writer.writerow([role_name, policy_name, policy_type, json.dumps(policy_document)])
            else:
                csv_writer.writerow([role_name, policy_name, policy_type, ''])

        for policy_name in inline_policies['PolicyNames']:
            policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            csv_writer.writerow([role_name, policy_name, 'Inline Policy', json.dumps(policy_document)])

    s3_client.put_object(Bucket=bucket_name, Key=csv_file_key, Body=output.getvalue())
    output.close()

    return {
        'statusCode': 200,
        'body': json.dumps('CSV file created and uploaded to S3')
    }
