function Export-ALAppLockerPolicy
{
<#
	.SYNOPSIS
		Export AaronLocker policies to AppLocker rule XML file.
	
	.DESCRIPTION
		Export AaronLocker policies to AppLocker rule XML file.
		This will create three files for each policy in the targetd folder:
		- AuditOnly
		- Enabled
		- NotConfigured
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.PARAMETER Policy
		The AaronLocker policy object to work with.
		Those objects are returned by 'Get-ALPolicy'.
	
	.PARAMETER Path
		The path to a folder to export to.
		Folder must exist, do not specify a file.
		By default exports to the current folder.
	
	.EXAMPLE
		PS C:\> Export-ALAppLockerPolicy
	
		Exports the currently active policy to the current folder, creating three XML files.
	
	.EXAMPLE
		PS C:\> Get-ALPolicy -List | Export-ALAppLockerPolicy -Path C:\Policies
	
		Exports all policies into XML files into the C:\Policies folder.
#>
	[CmdletBinding(DefaultParameterSetName = 'name')]
	Param (
		[Parameter(ParameterSetName = 'name')]
		[string]
		$PolicyName,
		
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'policy')]
		[AaronLocker.Policy[]]
		$Policy,
		
		[string]
		$Path = "."
	)
	
	begin
	{
		if ($PSCmdlet.ParameterSetName -eq 'name')
		{
			try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
			catch { Write-ALError -ErrorRecord $_ -Terminate }
		}
		try
		{
			$resolvedPath = Resolve-ALPath -Path $Path -Provider FileSystem -SingleItem
			if (-not (Get-Item -Path $resolvedPath).PSIsContainer) { throw "Path is not a folder: $($resolvedPath)" }
		}
		catch { Write-ALError -ErrorRecord $_ -Terminate }
	}
	process
	{
		#region Process by name
		if ($PolicyName)
		{
			Write-Verbose "Exporting the policy: $($PolicyName)"
			ConvertTo-ALAppLockerXML -PolicyName $PolicyName -EnforcementMode NotConfigured | Set-Content -Path "$($resolvedPath)\$($PolicyName).NotConfigured.xml" -Encoding Unicode -NoNewline
			ConvertTo-ALAppLockerXML -PolicyName $PolicyName -EnforcementMode AuditOnly | Set-Content -Path "$($resolvedPath)\$($PolicyName).AuditOnly.xml" -Encoding Unicode -NoNewline
			ConvertTo-ALAppLockerXML -PolicyName $PolicyName -EnforcementMode Enabled | Set-Content -Path "$($resolvedPath)\$($PolicyName).Enabled.xml" -Encoding Unicode -NoNewline
		}
		#endregion Process by name
		
		#region Process by object
		foreach ($policyObject in $Policy)
		{
			Write-Verbose "Exporting the policy: $($policyObject.Name)"
			ConvertTo-ALAppLockerXML -Policy $policyObject -EnforcementMode NotConfigured | Set-Content -Path "$($resolvedPath)\$($policyObject.Name).NotConfigured.xml" -Encoding Unicode -NoNewline
			ConvertTo-ALAppLockerXML -Policy $policyObject -EnforcementMode AuditOnly | Set-Content -Path "$($resolvedPath)\$($policyObject.Name).AuditOnly.xml" -Encoding Unicode -NoNewline
			ConvertTo-ALAppLockerXML -Policy $policyObject -EnforcementMode Enabled | Set-Content -Path "$($resolvedPath)\$($policyObject.Name).Enabled.xml" -Encoding Unicode -NoNewline
		}
		#endregion Process by object
	}
}