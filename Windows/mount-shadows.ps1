# Requires PowerShell 5.0+.

$drives = @{}; $links = @();

Get-WmiObject Win32_Volume | ForEach {
	$drives.Add($_.DeviceID, $_.DriveLetter)
}

Get-CimInstance -ClassName Win32_ShadowCopy | ForEach {
	$continue = $true
	$link = $drives[$_.VolumeName] + "\shadow" + ([string]$_.InstallDate).Replace(" ", "_").Replace(".", "-").Replace("/", "_").Replace(":", "-")
	$links += $link
	if (Test-Path $link) {
		Write-Host ("Can't mount drive " + $drives[$_.VolumeName] + " shadow from " + $_.InstallDate + " at " + $link + ", pathname already exists")
		switch -Regex (Read-Host "Delete link (Y|n)") {
		'^y?$' {(Get-Item $link).Delete()}
		default {$continue=$false}
		}
	}
	if ($continue) {
		cmd /c MKLINK /D $link ($_.DeviceObject + "\") >$null
		Write-Host ("Mounted drive " + $drives[$_.VolumeName] + " shadow from " + $_.InstallDate + " at " + $link)
	}
}

$links | ForEach {Write-Host $_}
switch -Regex (Read-Host "Delete links (Y|n)") {
'^y?$' {$links | ForEach {(Get-Item $_).Delete()}}
}

# vim:ft=sh
