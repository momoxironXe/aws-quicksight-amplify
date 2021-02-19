import json, os, boto3, base64, time
awsAccountId = roleArn = roleName = userName = email = groupName = dashboardRegion = identityRegion = quickSight = quickSightIdentity = None

def handler(event, context, mode):
    global awsAccountId, roleArn, roleName, userName, email, groupName, dashboardRegion, identityRegion, quickSight, quickSightIdentity
    try:
        
        #Get AWS Account Id
        awsAccountId = context.invoked_function_arn.split(':')[4]
        stage = 'Got account id'
        
        #Read in the environment variables
        dashboardRegion = os.environ['DashboardRegion']
        roleArn = os.environ['RoleArn']
        #Extract role name from arn
        roleName = roleArn.split('/')[1]
        
        if 'Suffix' in os.environ:
            suffix = os.environ['Suffix']
        else:
            suffix = ''
        groupName = 'EmbeddedDemoReaders'+suffix
        stage = 'Got env vars'
        
        #Read in the values passed to Lambda function as query string parameters
        openIdToken = event['queryStringParameters']['openIdToken']
        #Decode openIdToken and extract username and email fields.
        payload = json.loads(base64.b64decode(openIdToken.split('.')[1]+ "========"))
        userName = payload['cognito:username']
        email = payload['email']
        stage = 'Decoded token'
        
        #Assume role that has permissions on QuickSight
        sts = boto3.client('sts')
        assumedRole = sts.assume_role_with_web_identity(
            RoleArn = roleArn,
            RoleSessionName = userName,
            WebIdentityToken = openIdToken
        )
        stage = 'Assumed role'
        
        #Create boto3 session
        assumedRoleSession = boto3.Session(
                aws_access_key_id = assumedRole['Credentials']['AccessKeyId'],
                aws_secret_access_key = assumedRole['Credentials']['SecretAccessKey'],
                aws_session_token = assumedRole['Credentials']['SessionToken'],
            )
        stage = 'Created session'
        
        #Create QuickSight client
        quickSight = assumedRoleSession.client('quicksight',region_name= dashboardRegion)
        stage = 'Created QuickSight client'

        #Pick identityRegion from environment variable if available or else derive it.
        if 'IdentityRegion' in os.environ:
            identityRegion = os.environ['IdentityRegion']
        else:
            identityRegion = getIdentityRegion()
        stage = 'Derived QuickSight Identity Region'
        quickSightIdentity = assumedRoleSession.client('quicksight',region_name= identityRegion)
        stage = 'Created QuickSight client for Identity Region'
        
        if mode == 'getDashboardList':
            stage = 'Before getDashboardList call'
            response = getDashboardList(1)
            stage = 'After getDashboardList call'
            
        else: #mode == 'getUrl'
            stage = 'Before getUrl call'
            response = getUrl(1)
            stage = 'After getUrl call'
    
        return response
        
    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.handler function:'+stage+':'+str(e))



#Function that derives the identity region of your QuickSight account.
def getIdentityRegion():
    global awsAccountId, dashboardRegion, quickSight
    try:
        quickSight.describe_user(
            AwsAccountId = awsAccountId,
            Namespace = 'default',
            UserName = 'non-existent-user')
            
    except quickSight.exceptions.AccessDeniedException as e:
        #QuickSight manages all users and groups in the identity region of the account.
        #This can be different from the dashboard region provided as input to lambda.
        #Calls to APIs that deal with identity can be made against identity region only.
        #We made the call against dashboard region first. 
        #Since that didn't work, we will extract the identity region from the error message that is returned
        if str(e).find('but your identity region is') > -1 :
            identityRegion = str(e).split('but your identity region is ')[1].split('.')[0]
            return identityRegion
        raise Exception('Lambda GetQuickSightResponse.getIdentityRegion function:'+str(e))
        
    except quickSight.exceptions.ResourceNotFoundException as e:
        #Call went through which means the dashboardRegion we used is your identity region as well.
        identityRegion = dashboardRegion
        return identityRegion
        
    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.getIdentityRegion function:'+str(e))
   
    

#Get list of dashboards that user has access to. If user doesn't exist, trigger creation of user, group and group membership.    
def getDashboardList(recursionDepth):
    global awsAccountId, roleArn, roleName, userName, email, dashboardRegion, identityRegion, quickSight
    try:
        #Safeguard - If recursion depth is greater than 2, raise exception
        if recursionDepth > 2:
            raise Exception('getDashboardList: Deeper recursion than expected')
        recursionDepth += 1
            
        #Get list of dashboards that that the user has permission to access.
        response = quickSight.search_dashboards(
                        AwsAccountId = awsAccountId,
                        Filters = [
                                    {
                                        'Operator': 'StringEquals',
                                        'Name': 'QUICKSIGHT_USER',
                                        'Value': 'arn:aws:quicksight:' + identityRegion + ':' + awsAccountId + ':user/default/' + roleName + '/' + userName
                                    }
                                ]
                    )
                    
        #Repack the response to include just the dashboard names and ids
        dashboardList={}
        dashboardList['Dashboards']=[]
        for dashboard in response['DashboardSummaryList']:
            dashboardRepacked={}
            dashboardRepacked['Name']=dashboard['Name']
            dashboardRepacked['DashboardId']=dashboard['DashboardId']
            dashboardList['Dashboards'].append(dashboardRepacked)
        response = dashboardList
        #Return the dashboard list to calling function.
        return response
        
    except quickSight.exceptions.ResourceNotFoundException as e:
        #Register the user since user does not exist in QuickSight
        registerUser()
        #Add the user to EmbeddedDemoReaders group    
        createGroupMembership(1)
        #Make a recursive call. Dashboard list returned from this call is returned to handler function.
        return getDashboardList(recursionDepth)
        
    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.getDashboardList function:'+str(e))



def registerUser():
    global awsAccountId, roleArn, userName, email, quickSightIdentity
    try:

        #Register the user
        quickSightIdentity.register_user(
            AwsAccountId = awsAccountId,
            Namespace = 'default',
            IdentityType ='IAM',
            IamArn = roleArn,
            SessionName = userName,
            Email = email,
            UserRole ='READER'
            )

    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.registerUser function:'+str(e))
        


#Add user to embedded reader group. Create the group if it doesn't already exist.
def createGroupMembership(recursionDepth):
    global awsAccountId, roleName, userName, groupName, quickSightIdentity
    try:
        #Safeguard - If recursion depth is greater than 2, raise exception
        if recursionDepth > 2:
            raise Exception('createGroupMembership: Deeper recursion than expected')
        recursionDepth += 1

        #Add user to EmbeddedDemoReaders group
        quickSightIdentity.create_group_membership(
            AwsAccountId = awsAccountId,
            Namespace = 'default',
            MemberName = roleName + '/' + userName,
            GroupName = groupName)
            
    except quickSight.exceptions.ResourceNotFoundException as e:
        #If group is not present in QuickSight, create it.
        quickSightIdentity.create_group(
            AwsAccountId = awsAccountId,
            Namespace = 'default',
            GroupName = groupName)
        #Make a recursive call
        time.sleep(0.5) #adding half second wait just for added sa
        createGroupMembership(recursionDepth)
        
    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.createGroupMembership function:'+str(e))
        
        
        
#Get dynamic embed url        
def getUrl(recursionDepth):
    global awsAccountId, quickSight
    try:
        #Safeguard - If recursion depth is greater than 4, raise exception
        if recursionDepth > 4:
            raise Exception('getUrl: Deeper recursion than expected')
        recursionDepth += 1

        #Generate dynamic embed url. Parallel Ajax calls are made to retrieve the dashboard list and embed url.
        #So, a dummy dashboard id is passed below. 
        response = quickSight.get_dashboard_embed_url(
                        AwsAccountId = awsAccountId,
                        DashboardId = '20bc5811-13af-42a5-a359-3924768e72f1',
                        IdentityType = 'IAM',
                        SessionLifetimeInMinutes = 600,
                        UndoRedoDisabled = True,
                        ResetDisabled = True
                    )
        return response
        
    except quickSight.exceptions.QuickSightUserNotFoundException as e:
        #If user is not found, wait 2 seconds and try again.
        #Meanwhile, User will get added from the parallel call to retrieve dashboard list flow.
        registerUser()
        time.sleep(2)
        print(e)
        return getUrl(recursionDepth)
        
    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.getUrl function:'+str(e))