<#
.SYNOPSIS
Script used by Create-Policies.ps1 to identify EXE files that should be disallowed by AppLocker for non-admin use. Can be edited if necessary.

.DESCRIPTION
This script outputs a list of file paths under %windir% that need to be specifically disallowed by whitelisting rules.
The list of files is consumed by Create-Policies.ps1, which builds the necessary AppLocker rules to block them.
You can edit this file as needed for your environment, although it is recommended that none of the programs
identified in this script be removed.

Note: the solution also blocks the loading of PowerShell v2 modules - these blocks are hardcoded into the base XML file. This module
as currently designed can block only EXE files, not DLLs.
http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/

#>

# --------------------------------------------------------------------------------
# Files used to bypass whitelisting:

# Find the multiple instances of .NET executables that have been identified as whitelist bypasses.
# Create-Policies.ps1 will remove redundant information.
$dotnetProgramsToBlacklist =
    "InstallUtil.exe", 
    "IEExec.exe", 
    "RegAsm.exe", 
    "RegSvcs.exe", 
    "MSBuild.exe",
    "Microsoft.Workflow.Compiler.exe"
$dotnetProgramsToBlacklist | ForEach-Object {
    Get-ChildItem -Path $env:windir\Microsoft.NET -Recurse -Include $_ | ForEach-Object { $_.FullName }
}

"$env:windir\System32\mshta.exe"
"$env:windir\System32\PresentationHost.exe"
"$env:windir\System32\wbem\WMIC.exe"
# Note: also need Code Integrity rules to block other bypasses

# --------------------------------------------------------------------------------
# Files used by ransomware
"$env:windir\System32\cipher.exe"

# --------------------------------------------------------------------------------
# Block common credential exposure risk (also need to disable GUI option via registry, and SecondaryLogon service)
"$env:windir\System32\runas.exe"

