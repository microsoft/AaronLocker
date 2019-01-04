function Add-ALRule
{
<#
	.SYNOPSIS
		Adds a finished rule object to an AaronLocker policy.
	
	.DESCRIPTION
		Adds a finished rule object to an AaronLocker policy.
		This allows cloning rules from one policy to another.
	
	.PARAMETER Rule
		The rule(s) to add to the policy.
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.PARAMETER Force
		Force overwriting existing rules with the same label.
	
	.EXAMPLE
		PS C:\> Add-ALRule -Rule $Rule
	
		Adds the rule stored in $Rule to the default policy.
	
	.EXAMPLE
		PS C:\> Get-ALRule -PolicyName OneDrive | Add-ALRule -PolicyName ClientMGMT
	
		Copies all rules from the policy 'OneDrive' to the policy 'ClientMGMT'
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[AaronLocker.RuleBase[]]
		$Rule,
		
		[string]
		$PolicyName,
		
		[switch]
		$Force
	)
	
	begin
	{
		try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
		catch { Write-ALError -ErrorRecord $_ -Terminate }
		
		$policy = Get-ALPolicy -PolicyName $PolicyName
	}
	process
	{
		foreach ($ruleItem in $Rule)
		{
			if ($policy.Rules.Label -contains $ruleItem.Label)
			{
				if (-not $Force)
				{
					Write-Warning "Rule '$($ruleItem.Label)' already exists in policy $($PolicyName), skipping"
					continue
				}
				else
				{
					$oldRule = $policy.Rules | Where-Object Label -EQ $ruleItem.Label
					Write-Verbose "Removing rule '$($oldRule.Label)' from $($PolicyName)"
					$policy.Rules.Remove($oldRule)
				}
			}
			
			Write-Verbose "Adding rule '$($ruleItem.Label)' to $($PolicyName)"
			$policy.Rules.Add($ruleItem.Clone())
		}
	}
	end
	{
		Update-PolicyFile -PolicyName $PolicyName
	}
}