function Get-ALPolicy
{
<#
	.SYNOPSIS
		Returns the current policy object.
	
	.DESCRIPTION
		Returns the current policy object.
		Can instead list the available policy sets stored on the computer.
	
		Note on policies:
		AaronLocker manages rules in datasets called "policy".
		These can in fact be converted into AppLocker policies using the various tools provided in this module.
		This means:
		- Any number of rules (one or hundreds) can make up an AaronLocker "policy"
		- Any number of policies (one, two, dozens) can be converted into an AppLocker policy
		AaronLocker policies are persisted on disk and can be updated at any time later on.
	
	.PARAMETER PolicyName
		The name to filter the policies by.
	
	.EXAMPLE
		PS C:\> Get-ALPolicy
	
		Shows the current policy
	
	.EXAMPLE
		PS C:\> Get-ALPolicy -List
	
		List all locally available policies
	
	.EXAMPLE
		PS C:\> Get-ALPolicy -List -PolicyName OneDrive
	
		Return only the available info on the policy named "OneDrive"
#>
	[OutputType([AaronLocker.Policy])]
	[CmdletBinding()]
	param (
		[Parameter(Position = 0)]
		[string]
		$PolicyName
	)
	
	process
	{
		if (-not $PSBoundParameters.ContainsKey("PolicyName"))
		{
			$script:_PolicyData[$script:config.ActivePolicy]
		}
		else
		{
			$script:_PolicyData.Values | Where-Object Name -Like $PolicyName
		}
	}
}