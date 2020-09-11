# Modified version of Invoke-Assembly
Function Invoke-Assembly {
	[CmdletBinding()]
		Param (		
			[Parameter()]
			[String[]]$Arguments = ""
	)
	$foundMain = $false
	$asm_data = "~~ASSEMBLY~~"
	try {
		$assembly = [Reflection.Assembly]::Load([Convert]::FromBase64String($asm_data))
	}
	catch {
		Write-Output "[!] Could not load assembly. Is it in COFF/MSIL/.NET format?"
		throw
	}
	foreach($type in $assembly.GetExportedTypes()) {
		foreach($method in $type.GetMethods()) {
			if($method.Name -eq "Main") {
				$foundMain = $true
				if($Arguments[0] -eq "") {
					Write-Output "[*] Attempting to load assembly with no arguments"
				}
				else {
					Write-Output "[*] Attempting to load assembly with arguments: $Arguments"
				}
				$a = (,[String[]]@($Arguments))
				try {
					$output = $method.Invoke($null, $a)
					Write-Output $output
				}
				catch {
					Write-Output "[!] Could not invoke assembly or program crashed during execution"
					throw
				}
			}
		}
	}
	if(!$foundMain) {
		Write-Output "[!] Could not find public Main() function. Did you set the namespace as public?"
		throw
	}
}
Invoke-Assembly -Arguments ~~ARGUMENTS~~