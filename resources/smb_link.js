var filepath = "C:\\users\\localadmin\\desktop\\bridge.txt"

var fdr = fso.OpenTextFile(filepath)
var updata = fdr.ReadAll()
fdr.close()

if(updata !== jsondata+"\r\n") { // Windows adds a \r\n at the end of file reads
  WScript.Echo("Debug: Upstream Recieved: " + updata)
  var fdw = fso.OpenTextFile(filepath, 2) // mode 2 = write
  fdw.WriteLine(filedata)
  fdw.close()
}
