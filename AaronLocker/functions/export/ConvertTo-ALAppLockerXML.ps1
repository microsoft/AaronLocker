function ConvertTo-ALAppLockerXML
{
<#
	.SYNOPSIS
		Generates AppLocker XML data from AaronLocker policies.
	
	.DESCRIPTION
		Generates AppLocker XML data from AaronLocker policies.
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.PARAMETER Policy
		The AaronLocker policy object to work with.
		Those objects are returned by 'Get-ALPolicy'.
	
	.PARAMETER EnforcementMode
		Whether the generated XML is being enforced, audited or unconfigured.
	
	.EXAMPLE
		PS C:\> ConvertTo-ALAppLockerXML
	
		Returns the AppLocker XML of the currently active policy.
#>
	[OutputType([System.String])]
	[CmdletBinding(DefaultParameterSetName = 'name')]
	Param (
		[Parameter(ParameterSetName = 'name')]
		[string]
		$PolicyName,
		
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'policy')]
		[AaronLocker.Policy[]]
		$Policy,
		
		[AaronLocker.EnforcementMode]
		$EnforcementMode = [AaronLocker.EnforcementMode]::NotConfigured
	)
	
	begin
	{
		if ($PSCmdlet.ParameterSetName -eq 'name')
		{
			try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
			catch { Write-ALError -ErrorRecord $_ -Terminate }
		}
	}
	process
	{
		#region Process by name
		if ($PolicyName)
		{
			# Should only return one policy ever - Resolve-ALPolicy will only resolve to one policy currently.
			# Still looping in case this design decision changes later on.
			$policyObjects = Get-ALPolicy -PolicyName $PolicyName
			foreach ($policyObject in $policyObjects)
			{
				Write-Verbose "Returning XML of $($policyObject.Name)"
				$policyObject.GetXml($EnforcementMode)
			}
		}
		#endregion Process by name
		
		#region Process by object
		foreach ($policyObject in $Policy)
		{
			Write-Verbose "Returning XML of $($policyObject.Name)"
			$policyObject.GetXml($EnforcementMode)
		}
		#endregion Process by object
	}
}