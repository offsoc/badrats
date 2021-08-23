// This file is used as a standin downstream "client" (rat) for testing the peer-to-peer SMB UNC file comm channel 
// This file should be deleted after the SMB rat is developed

var filepath = "C:\\users\\localadmin\\desktop\\bridge.txt"
var filedata = '{ "p":[ {"type": "hta", "id": 3082961485, "un": "kclark", "hn": "WS01"}, {"type": "js", "id": 11223344, "un": "Administrator", "hn": "DC"} ] }'
var fso = new ActiveXObject("Scripting.FileSystemObject")


var fd = fso.CreateTextFile(filepath)
fd.close()
//var fdr = fso.OpenTextFile(filepath)
var fdw = fso.OpenTextFile(filepath, 2) // mode 2 = write
fdw.WriteLine(filedata)
fdw.close()

while (true) {
    var fdr = fso.OpenTextFile(filepath)
    var updata = fdr.ReadAll()
    fdr.close()
    
    if(updata !== filedata+"\r\n") { // Windows adds a \r\n at the end of file reads
        //WScript.Echo("Downstream Recieved: " + updata)
        var fdw = fso.OpenTextFile(filepath, 2) // mode 2 = write
        fdw.WriteLine(filedata)
        fdw.close()
    }
    else {
        
    }
    
    WScript.Sleep(4000)
}
