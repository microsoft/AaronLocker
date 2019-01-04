function Get-ALRule
{
<#
	.SYNOPSIS
		Get rules from the specified AaronLocker policy.
	
	.DESCRIPTION
		Get rules from the specified AaronLocker policy.
	
	.PARAMETER Label
		The label of the rule to search by.
	
	.PARAMETER Type
		Only return rules of the specified type(s).
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.EXAMPLE
		PS C:\> Get-ALRule
	
		Lists all rules under the current policy.
	
	.EXAMPLE
		PS C:\> Get-ALRule -Type Path
	
		Lists all path rules under the current policy.
	
	.EXAMPLE
		PS C:\> Get-ALRule -Type Hash -PolicyName OneDrive
	
		Lists all hash rules under the OneDrive policy.
#>
	[CmdletBinding()]
	Param (
		[string]
		$Label = '*',
		
		[AaronLocker.RuleType[]]
		$Type,
		
		[string]
		$PolicyName
	)
	
	begin
	{
		try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
		catch { Write-ALError -ErrorRecord $_ -Terminate }
		
		$policy = Get-ALPolicy -PolicyName $PolicyName
	}
	process
	{
		$policy.Rules | Where-Object {
			if ($_.Label -notlike $Label) { return $false }
			if (($Type) -and ($_.Type -notin $Type)) { return $false }
			$true
		}
	}
}