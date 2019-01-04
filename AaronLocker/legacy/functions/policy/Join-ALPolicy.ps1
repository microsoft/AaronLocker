function Join-ALPolicy
{
<#
	.SYNOPSIS
		Merges multiple policies into a single combined policy.
	
	.DESCRIPTION
		Merges multiple policies into a single combined policy.
	
	.PARAMETER Policy
		The policy objects to combine.
		Must be objects as returned by New-AppLockerPolicy.
	
	.EXAMPLE
		PS C:\> $policies | Join-ALPolicy
	
		Combines all policies stored in $policies into a single one.
#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true, Mandatory = $true)]
		$Policy
	)
	
	begin
	{
		$policies = $null
	}
	process
	{
		foreach ($policyItem in $Policy)
		{
			if ($null -eq $policies) { $policies = $policyItem }
			else { $policies.Merge($policyItem) }
		}
	}
	end
	{
		$policies
	}
}