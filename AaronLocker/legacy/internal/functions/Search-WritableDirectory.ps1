function Search-WritableDirectory
{
<#
	.SYNOPSIS
		Enumerates "user-writable" subdirectories.
	
	.DESCRIPTION
		Enumerates subdirectories that are writable by accounts other than a set of
		known admin or admin-equivalent entities (including members of the local
		Administrators group). The goal is to list user-writable directories in
		which end user program execution should be disallowed via AppLocker.
		You should run this script with administrative rights to avoid access-
		denied errors.
		
		NOTE: Requires Sysinternals AccessChk.exe:
		https://technet.microsoft.com/sysinternals/accesschk
		https://download.sysinternals.com/files/AccessChk.zip
		NOTE: Requires Windows PowerShell 5.1 or newer (relies on Get-LocalGroup and
		Get-LocalGroupMember cmdlets).
		
		Note: this script does not discover user-writable files. A user-writable
		file in a non-writable directory presents a similar risk, as a non-admin
		can overwrite it with arbitrary content and execute it.
	
	.PARAMETER RootDirectory
		The starting directory for the permission enumeration.
	
	.PARAMETER ShowGrantees
		If set, output includes the names of the non-admin entities that have write permissions
	
	.PARAMETER DontFilterNTService
		By default, this script ignores access granted to NT SERVICE\ accounts (SID beginning with S-1-5-80-).
		If this switch is set, this script does not ignore that access, except for access granted to NT SERVICE\TrustedInstaller.
	
	.PARAMETER OutputXML
		If set, output is formatted as XML.
	
	.PARAMETER KnownAdmins
		Optional: additional list of known administrative users and groups.
	
	.EXAMPLE
		PS C:\> Search-WritableDirectory -RootDirectory C:\Windows\System32
		
		Output:
		C:\Windows\System32\FxsTmp
		C:\Windows\System32\Tasks
		C:\Windows\System32\Com\dmp
		C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
		C:\Windows\System32\spool\PRINTERS
		C:\Windows\System32\spool\SERVERS
		C:\Windows\System32\spool\drivers\color
		C:\Windows\System32\Tasks\Microsoft IT Diagnostics Utility
		C:\Windows\System32\Tasks\Microsoft IT VPN
		C:\Windows\System32\Tasks\WPD
		C:\Windows\System32\Tasks\Microsoft\Windows\RemoteApp and Desktop Connections Update
		C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
		C:\Windows\System32\Tasks\Microsoft\Windows\WCM
		C:\Windows\System32\Tasks\Microsoft\Windows\PLA\System
	
	.EXAMPLE
		PS C:\> Search-WritableDirectory -RootDirectory C:\Windows\System32 -ShowGrantees
		
		Output:
		C:\Windows\system32\FxsTmp
		  BUILTIN\Users
		C:\Windows\system32\Tasks
		  NT AUTHORITY\Authenticated Users
		C:\Windows\system32\Com\dmp
		  BUILTIN\Users
		C:\Windows\system32\Microsoft\Crypto\RSA\MachineKeys
		  Everyone
		C:\Windows\system32\spool\PRINTERS
		  BUILTIN\Users
		C:\Windows\system32\spool\SERVERS
		  BUILTIN\Users
		C:\Windows\system32\spool\drivers\color
		  BUILTIN\Users
		C:\Windows\system32\Tasks\Microsoft IT Diagnostics Utility
		  NT AUTHORITY\Authenticated Users
		C:\Windows\system32\Tasks\Microsoft IT VPN
		  NT AUTHORITY\Authenticated Users
		C:\Windows\system32\Tasks\WPD
		  NT AUTHORITY\Authenticated Users
		  aaronmar5\aaronmaradmin
		C:\Windows\system32\Tasks\Microsoft\Windows\RemoteApp and Desktop Connections Update
		  NT AUTHORITY\Authenticated Users
		C:\Windows\system32\Tasks\Microsoft\Windows\SyncCenter
		  BUILTIN\Users
		C:\Windows\system32\Tasks\Microsoft\Windows\WCM
		  BUILTIN\Users
		C:\Windows\system32\Tasks\Microsoft\Windows\PLA\System
		  Everyone
	
	.EXAMPLE
		PS C:\> $x = [xml](Search-WritableDirectory -RootDirectory C:\Windows\System32 -ShowGrantees -OutputXML)
		PS C:\> $x.root.dir | Sort-Object name
		
		Output:
		name                                                                            Grantee
		----                                                                            -------
		C:\Windows\System32\Com\dmp                                                     BUILTIN\Users
		C:\Windows\System32\FxsTmp                                                      BUILTIN\Users
		C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys                            Everyone
		C:\Windows\System32\spool\drivers\color                                         BUILTIN\Users
		C:\Windows\System32\spool\PRINTERS                                              BUILTIN\Users
		C:\Windows\System32\spool\SERVERS                                               BUILTIN\Users
		C:\Windows\System32\Tasks                                                       NT AUTHORITY\Authenticated Users
		C:\Windows\System32\Tasks\Microsoft IT Diagnostics Utility                      NT AUTHORITY\Authenticated Users
		C:\Windows\System32\Tasks\Microsoft IT VPN                                      NT AUTHORITY\Authenticated Users
		C:\Windows\System32\Tasks\Microsoft\Windows\PLA\System                          Everyone
		C:\Windows\System32\Tasks\Microsoft\Windows\RemoteApp and Desktop Connection... NT AUTHORITY\Authenticated Users
		C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter                          BUILTIN\Users
		C:\Windows\System32\Tasks\Microsoft\Windows\WCM                                 BUILTIN\Users
		C:\Windows\System32\Tasks\WPD                                                   {NT AUTHORITY\Authenticated Users, vm-t2408\admin}
	
	.LINK
		Sysinternals AccessChk available here:
		https://technet.microsoft.com/sysinternals/accesschk
		https://download.sysinternals.com/files/AccessChk.zip
#>
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true)]
		[String]
		$RootDirectory,
		
		[switch]
		$ShowGrantees,
		
		[switch]
		$DontFilterNTService,
		
		[switch]
		$OutputXML,
		
		[String[]]
		$KnownAdmins
	)
	
	if (-not (Test-AccessChk))
	{
		$errMsg = @"
Scanning for writable subdirectories requires that Sysinternals AccessChk.exe be available.
Please download it and use Set-ALConfiguration -PathAccessChk "<path>" to register its location.
"AccessChk.exe was not found. Exiting...
"@
		throw $errMsg
	}
	
	# If RootDirectory has a trailing backslash, remove it (AccessChk doesn't handle it correctly).
	if ($RootDirectory.EndsWith("\")) { $RootDirectory = $RootDirectory.Substring(0, $RootDirectory.Length - 1) }
	
	# Entities for which to ignore write permissions.
	# TrustedInstaller is always ignored; other NT SERVICE\ accounts are filtered
	# out later (too many to list and too many unknown).
	# The Package SIDs below (S-1-15-2-*) are associated with microsoft.windows.fontdrvhost and
	# are not a problem. AppContainers never grant additional access; they only reduce access.
	$FilterOut0 = @"
S-1-3-0
S-1-5-18
S-1-5-19
S-1-5-20
S-1-5-32-544
S-1-5-32-549
S-1-5-32-550
S-1-5-32-551
S-1-5-32-577
S-1-5-32-559
S-1-5-32-568
NT SERVICE\TrustedInstaller
S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069167804-1277922394
S-1-15-2-95739096-486727260-2033287795-3853587803-1685597119-444378811-2746676523
"@
	# Filter all the above plus caller-supplied "known admins"
	$FilterOut = ($FilterOut0.Split("`n`r") + $KnownAdmins | Where-Object Length -gt 0) -join ","
	# Add all members of the local Administrators group, as the Effective Permissions
	# APIs consider them to be administrators also.
	# For some reason, Get-LocalGroup/Get-LocalGroupMember aren't available on WMFv5.0 on Win7;
	# Verify whether command exists before using it. The commands are available on Win7 in v5.1.
	if ($null -ne (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue))
	{
		#TODO: Detect and handle case where this cmdlet fails - disconnected and the admins group contains domain SIDs that can't be resolved.
		#FWIW, NET LOCALGROUP Administrators doesn't report these entries either.
		#Also fails on AAD-joined, with unresolved SIDs beginning with S-1-12-1-...
		Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | ForEach-Object { $FilterOut += "," + $_.SID.Value }
	}
	
	$currfile = ""
	
	if ($OutputXML) { "<root>" }
	
	$bInElem = $false
	
	& $script:config.PathAccessChk /accepteula -nobanner -w -d -s -f $FilterOut $RootDirectory | ForEach-Object {
		if ($_.StartsWith("  ") -or $_.Length -eq 0)
		{
			if ($_.StartsWith("  RW ") -or $_.StartsWith("   W "))
			{
				$grantee = $_.Substring(5).Trim()
				if ($DontFilterNTService -or (!$grantee.StartsWith("NT SERVICE\") -and !$grantee.StartsWith("S-1-5-80-")))
				{
					if ($currfile.Length -gt 0)
					{
						if ($OutputXML)
						{
							# Path name has to be escaped for XML
							"<dir name=`"" + [Security.SecurityElement]::Escape($currfile) + "`">"
						}
						else
						{
							$currfile
						}
						$currfile = ""
						$bInElem = $true
					}
					if ($ShowGrantees)
					{
						if ($OutputXML)
						{
							"<Grantee>" + $grantee + "</Grantee>"
						}
						else
						{
							"  " + $grantee
						}
					}
				}
			}
		}
		else
		{
			if ($bInElem -and $OutputXML) { "</dir>" }
			$currfile = $_
			$bInElem = $false
		}
	}
	
	if ($bInElem -and $OutputXML) { "</dir>" }
	if ($OutputXML) { "</root>" }
}