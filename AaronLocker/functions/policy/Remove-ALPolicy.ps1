function Remove-ALPolicy
{
<#
	.SYNOPSIS
		Removes an AaronLocker policy.
	
	.DESCRIPTION
		Removes an AaronLocker policy.
		This removes the object in memory and the backing file from disk.
		Please note that this does NOT have any effect on actively configured AppLocker policies.
		This command is designed to clear legacy policies.
	
	.PARAMETER PolicyName
		The name of the policy to remove.
	
	.PARAMETER Policy
		A policy object returned by Get-ALPolicy.
	
	.EXAMPLE
		PS C:\> Remove-ALPolicy -PolicyName 'OneDrive'
	
		Removes an AaronLocker policy named OneDrive.
#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param (
		[Parameter(Mandatory = $true, ParameterSetName = 'name')]
		[string]
		$PolicyName,
		
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'policy')]
		[AaronLocker.Policy[]]
		$Policy
	)
	
	process
	{
		#region Delete by name
		if ($PolicyName)
		{
			Write-Verbose "$($PolicyName): Starting to process"
			try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
			catch { Write-ALError -ErrorRecord $_ -Terminate }
			
			# Implement ShouldProcess to terminate if it should NOT proceed
			if (-not $PSCmdlet.ShouldProcess($PolicyName, 'Removing AaronLocker Policy')) { return }
			
			Write-Verbose "$($PolicyName): Removing policy object"
			$null = $script:_PolicyData.Remove($PolicyName)
			if (Test-Path "$($script:_RulesFolder)\$($PolicyName).policy.clixml")
			{
				Write-Verbose "$($PolicyName): Removing policy file"
				Remove-Item "$($script:_RulesFolder)\$($PolicyName).policy.clixml"
			}
			else { Write-Verbose "$($PolicyName): No policy file found!" }
		}
		#endregion Delete by name
		
		#region Delete by object
		foreach ($policyObject in $Policy)
		{
			Write-Verbose "$($policyObject.Name): Starting to process"
			try { $polName = Resolve-ALPolicy -PolicyName $policyObject.Name }
			catch { Write-ALError -ErrorRecord $_ -Continue }
			
			# Implement ShouldProcess to terminate if it should NOT proceed
			if (-not $PSCmdlet.ShouldProcess($polName, 'Removing AaronLocker Policy')) { continue }
			
			Write-Verbose "$($polName): Removing policy object"
			$null = $script:_PolicyData.Remove($polName)
			if (Test-Path "$($script:_RulesFolder)\$($polName).policy.clixml")
			{
				Write-Verbose "$($polName): Removing policy file"
				Remove-Item "$($script:_RulesFolder)\$($polName).policy.clixml"
			}
			else { Write-Verbose "$($polName): No policy file found!" }
		}
		#endregion Delete by object
	}
	end
	{
		if ($script:_PolicyData.Keys -notcontains $script:config.ActivePolicy)
		{
			if ($script:_PolicyData.Keys.Count -gt 0)
			{
				Write-Warning ("The active policy has been removed, enabling {0} as active policy" -f $script:_PolicyData.Keys[0])
				Set-ALActivePolicy -PolicyName $script:_PolicyData.Keys[0]
			}
			else
			{
				Write-Warning "No policy left! Creating a new 'default' policy and enabling it as active policy."
				New-ALPolicy -PolicyName 'default' -Description 'The default AaronLocker policy' -Activate
			}
		}
	}
}
