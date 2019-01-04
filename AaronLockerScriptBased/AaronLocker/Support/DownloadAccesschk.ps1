<#
.SYNOPSIS
Download Sysinternals accesschk.exe into the parent directory above this script's directory.

TODO: Maybe add a required -AcceptEula switch
#>

# Identify the directory above this script's directory (presumably the main "AaronLocker" directory).
$thisDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$targetDir = [System.IO.Directory]::GetParent($thisDir).FullName

Invoke-WebRequest -Uri https://live.sysinternals.com/accesschk.exe -OutFile (Join-Path $targetDir "accesschk.exe")
#TODO: Verify that Invoke-Request succeeded.

#TODO: Set the LastWriteTime to match
