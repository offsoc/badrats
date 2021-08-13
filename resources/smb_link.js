var filepath = "C:\\users\\localadmin\\desktop\\bridge.txt"

var fdr = fso.OpenTextFile(filepath)
var updata = fdr.ReadAll()
fdr.close()

if(updata !== jsondata+"\r\n") { // Windows adds a \r\n at the end of file reads

  // assume ~positive intent~ valid results ... definitely nothing can go wrong here
  checkin += updata.split("[")[1].split("]")[0] + ", " // add peer rat packages to checkin data
  var fdw = fso.OpenTextFile(filepath, 2) // mode 2 = write
  fdw.WriteLine(jsondata)
  fdw.close()
}
