@{
	# Files used to bypass whitelisting:
	DotNetApplications = @(
		"InstallUtil.exe"
		"IEExec.exe"
		"RegAsm.exe"
		"RegSvcs.exe"
		"MSBuild.exe"
	)
	
	FullPath		   = @(
		# Files used to bypass whitelisting:
		"$env:windir\System32\mshta.exe"
		"$env:windir\System32\PresentationHost.exe"
		"$env:windir\System32\wbem\WMIC.exe"
		# Note: also need Code Integrity rules to block other bypasses
		
		# Files used by ransomware
		"$env:windir\System32\cipher.exe"
		
		# Block common credential exposure risk (also need to disable GUI option via registry, and SecondaryLogon service)
		"$env:windir\System32\runas.exe"
	)
}