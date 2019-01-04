function Remove-ALRule
{
<#
	.SYNOPSIS
		Removes rules from AaronLocker policies.
	
	.DESCRIPTION
		Removes rules from AaronLocker policies.
	
	.PARAMETER Rule
		The rule(s) to remove from the policy.
		Actual comparisson is done using the label property.
	
	.PARAMETER Label
		The label by which to look for rules to remove.
		Supports wildcards.
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.PARAMETER Confirm
		If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.
	
	.PARAMETER WhatIf
		If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.
	
	.EXAMPLE
		PS C:\> Remove-ALRule -Rule $Rule
	
		Removes the specified rule from the current policy.
	
	.EXAMPLE
		PS C:\> Get-ALRule -PolicyName OneDrive | Remove-ALRule -PolicyName ClientMGMT
	
		Removes all rules in the policy ClientMGMT that occur in the policy OneDrive
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[AaronLocker.RuleBase[]]
		$Rule,
		
		[string[]]
		$Label,
		
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
		#region By Rule Object
		foreach ($ruleItem in $Rule)
		{
			if ($policy.Rules.Label -notcontains $ruleItem.Label)
			{
				Write-Warning "Rule '$($ruleItem.Label)' does not exist in policy $($PolicyName), skipping"
				continue
			}
			
			$oldRule = $policy.Rules | Where-Object Label -EQ $ruleItem.Label
			if ($PSCmdlet.ShouldProcess($oldRule.Label, "Remove from $($PolicyName)"))
			{
				Write-Verbose "Removing rule '$($oldRule.Label)' from $($PolicyName)"
				$policy.Rules.Remove($oldRule)
			}
		}
		#endregion By Rule Object
		
		#region By Rule Name / Label
		foreach ($labelItem in $Label)
		{
			if (-not ($policy.Rules.Label -like $labelItem))
			{
				Write-Warning "Could not find a rule matching '$($labelItem)' in policy $($PolicyName), skipping"
				continue
			}
			$oldRules = $policy.Rules | Where-Object Label -EQ $ruleItem.Label
			foreach ($oldRule in $oldRules)
			{
				if ($PSCmdlet.ShouldProcess($oldRule.Label, "Remove from $($PolicyName)"))
				{
					Write-Verbose "Removing rule '$($oldRule.Label)' from $($PolicyName)"
					$policy.Rules.Remove($oldRule)
				}
			}
		}
		#endregion By Rule Name / Label
	}
	end
	{
		Update-PolicyFile -PolicyName $PolicyName
	}
}