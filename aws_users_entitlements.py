import json
import boto3


def filter_services(policy):
    """
    Filter service function will parse the Permission set policy and returns AWS services which are part of the policy
    function only looks at the resources with Actions as Allow.

    :param policy: Permission Set Policy
    :return: Returns list of AWS Services which are part of AWS resources
    """
    statements = json.loads(policy)
    aws_resources = []
    #Iterate through set of statements inside a permission policy
    for statement in statements["Statement"]:
        if statement['Effect'] == 'Allow':
            # List resources with Allow action
            resources = statement['Action']
            # Append / Create a list for AWS resources
            if type(resources) == list:
                for resource in resources:
                    aws_resources.append(resource.split(':')[0])
            else:
                aws_resources.append(resources.split(':')[0])
    #Returns back a set of AWS resources
    return set(aws_resources)


def parse_permissions(permission_set_arn):
    """
    Function will parse the permission set ARN
    Function will find all the attached managed policies
    Attached managed policy and it's ARN will be a part of AWS IAM Policy
    Get the IAM policy document and parse it to the filter service function
    :param permission_set_arn: Permission Set
    :return: List of AWS Services allowed inside an IAM policy
    """
    global SERVICES_ALLOWED
    client = boto3.client('sso-admin', 'us-east-1')
    response = client.list_managed_policies_in_permission_set(
        InstanceArn='arn:aws:sso:::instance/ssoins-XXXXXXXXXX',
        PermissionSetArn=permission_set_arn,
        MaxResults=99,
        NextToken=''
    )
    if response['AttachedManagedPolicies'] != []:
        iam_client = boto3.client('iam', 'us-east-1')
        policy = iam_client.get_policy(PolicyArn=response['AttachedManagedPolicies'][0]['Arn'])
        response = iam_client.get_policy_version(
            PolicyArn=response['AttachedManagedPolicies'][0]['Arn'],
            VersionId=policy['Policy']['DefaultVersionId']
        )
        SERVICES_ALLOWED = filter_services(json.dumps(response['PolicyVersion']['Document']))
        # print(response)
    return SERVICES_ALLOWED


def lambda_handler(event, context):
    """
    Lambda Handler will read through all the permission sets from AWS Identity Center.
    After reading permission sets, lambda code will iterate and list permission set to account assignments mapping
    After the permission set and user assignments, code will parse the permission sets to list set of AWS Services uses have access to.
    Code creates a map between user and services assignment.
    At the end of it, code spits out Graph QL

    :return: Graph QL statements about users, permissions and AWS Services
    """
    # List assigned permissions sets from the Identity Center
    client_id = boto3.client('identitystore', 'us-east-1')
    # Access sso-admin object
    client = boto3.client('sso-admin', 'us-east-1')
    #List Permission Sets using your Identity Center ARN value
    response = client.list_permission_sets(
        InstanceArn='arn:aws:sso:::instance/ssoins-XXXXXXXXXXXX',
        NextToken='',
        MaxResults=99
    )
    #Capture the response from a permission set
    permission_set = response['PermissionSets']
    #Final Use to role mapping would hold mapping between a user and AWS Service
    final_user_role_mapping = {}
    #Iterate through the permission set for permissions captured earlier
    # This loop will help to read User Account and Permission Set combination
    for permission in permission_set:
        # List all the assignments between a permission and user
        response = client.list_account_assignments(
            InstanceArn='arn:aws:sso:::instance/ssoins-XXXXXXXXXXX',
            AccountId='989898989898',
            PermissionSetArn=permission,
            MaxResults=99,
            NextToken=''
        )
        #Capture and filter the response for Permission set ARN + Uer/ Principal attached to it
        #if response['AccountAssignments'] != []:
        for response in response['AccountAssignments']:
            permission_set_arn = response['PermissionSetArn']
            # Get user Details, IdentityStore ID can be captured from AWS identity Center store
            response1 = client_id.describe_user(
                IdentityStoreId='d-000000000',
                UserId=response['PrincipalId']
            )
            # Get the user name
            assigned_username = response1['UserName']
            #Function parses permission sets and returns list of services for a permission
            services = parse_permissions(permission_set_arn)
            #Create a mapping between a user and assigned AWS services
            final_user_role_mapping[assigned_username] = services

    # List out users and list of services user has access to..
    print(final_user_role_mapping)


