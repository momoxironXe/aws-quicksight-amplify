import json, os, re, base64
import GetQuickSightResponse

def handler(event, context):
    try:
        #This lambda function along with APIGateway is being used to mimic embedding QuickSight dashboard into a static web page.
        #When mode is passed in as static or when not specified, this function returns a static single page HTML.
        #When mode is set to getDashboardList or getUrl, QuickSight APIs are called to get the list of dashboards or embed url 
        #and this is returned the static html page that made this request.
        mode='static'
        response={} 
        if event['queryStringParameters'] is None:
            mode='static'
        elif 'mode' in event['queryStringParameters'].keys():
            if event['queryStringParameters']['mode'] in ['static','getUrl','getDashboardList']:
                mode=event['queryStringParameters']['mode']
            else:
                mode='unsupportedValue'
        
        
        #If mode is static, get the api gateway url from event. 
        #In a truly static use case (like an html page getting served out of S3, S3+CloudFront),this url can be hard coded in the html file
        #Deriving this from event and replacing in html file at run time to avoid having to come back to lambda 
        #to specify the api gateway url while you are building this sample in your environment.
        if mode == 'static':
            htmlFile = open('content/dashboard-embed-sample.html', 'r')
            if event['headers'] is None or event['requestContext'] is None:
                apiGatewayUrl = 'ApiGatewayUrlIsNotDerivableWhileTestingFromApiGateway'
            else:
                apiGatewayUrl = 'https://' + event['headers']['Host']+event['requestContext']['path']
    
            #Read contents of sample html file
            htmlContent = htmlFile.read()
        
            #Read logo file in base64 format
            logoFile = open('content/Logo.png','rb')
            logoContent = base64.b64encode(logoFile.read())
        
            #Read in the environment variables
            cognitoDomainUrl = os.environ['CognitoDomainUrl']
            cognitoClientId = os.environ['CognitoClientId']
            
            #Replace place holders.
            #logoContent when cast to str is in format b'content'.
            #Array notation is used to extract just the content.
            htmlContent = re.sub('<LogoFileBase64>', str(logoContent)[2:-1], htmlContent)
            
            #Replace API Gateway url placeholder
            htmlContent = re.sub('<apiGatewayUrl>', apiGatewayUrl, htmlContent)
            htmlContent = re.sub('<cognitoDomainUrl>', cognitoDomainUrl, htmlContent)
            htmlContent = re.sub('<cognitoClientId>', cognitoClientId, htmlContent)
    
            #Return HTML. 
            return {'statusCode':200,
                'headers': {"Content-Type":"text/html"},
                'body':htmlContent
                }
                
        elif mode in [ 'getUrl', 'getDashboardList' ]:
            response = GetQuickSightResponse.handler(event, context, mode)
           
            #Return response from Quicksight.
            #Access-Control-Allow-Origin doesn't come into play in this sample as origin is the API Gateway url itself.
            #When using the static mode wherein initial static HTML is loaded from a different domain, this header becomes relevant.
            #You should change to the specific origin domain in that scenario to avoid CORS error.  
            return {'statusCode':200,
                    'headers': {"Access-Control-Allow-Origin": "*",
                                "Content-Type":"text/plain"},
                    'body':json.dumps(response)
                    } 
        else: #unsupported mode
            #Return error along with list of valid mode values.
            return {'statusCode':400,
                    'headers': {"Access-Control-Allow-Origin": "*",
                                "Content-Type":"text/plain"},
                    'body':json.dumps('Error: unsupported mode used. Valid values are static, getUrl, getDashboardList')
                    } 
    except Exception as e: #catch all
        return {'statusCode':400,
                'headers': {"Access-Control-Allow-Origin": "*",
                            "Content-Type":"text/plain"},
                'body':json.dumps('Error: ' + str(e))
                }     
