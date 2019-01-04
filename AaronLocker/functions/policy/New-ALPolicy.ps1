function New-ALPolicy
{
<#
	.SYNOPSIS
		Create a new AaronLocker policy
	
	.DESCRIPTION
		Create a new AaronLocker policy.
		This policy can then receive rules and be converted to other, useful formats.
	
	.PARAMETER PolicyName
		The name of the AaronLocker policy to create.
	
	.PARAMETER Description
		A suitable description of the policy
	
	.PARAMETER Force
		Overwrite existing policy if present
	
	.PARAMETER Activate
		Configures the created policy as the new active (=default) policy.
	
	.EXAMPLE
		PS C:\> New-ALPolicy -PolicyName OneDrive
	
		Creates a new AaronLocker policy named OneDrive.
	
	.EXAMPLE
		PS C:\> New-ALPolicy -PolicyName TwoDrive -Description 'Some Text' -Force -Activate
	
		Creates a new AaronLocker policy named TwoDrive, with some arbitrary description.
		It will overwrite any already existing policy of that name and it will set the new policy as the default policy to work against.
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[string]
		$PolicyName,
		
		[string]
		$Description,
		
		[switch]
		$Force,
		
		[switch]
		$Activate
	)
	
	begin
	{
		if (-not $Force -and $script:_PolicyData.ContainsKey($PolicyName))
		{
			Write-ALError -Message "Policy $PolicyName exists already. Use '-Force' to overwrite." -Terminate
		}
	}
	process
	{
		$policy = New-Object AaronLocker.Policy
		$policy.Name = $PolicyName
		$policy.Description = $Description
		$script:_PolicyData[$PolicyName] = $policy
		Update-PolicyFile -PolicyName $policy.Name
	}
	end
	{
		if ($Activate)
		{
			Set-ALActivePolicy -PolicyName $PolicyName
		}
	}
}
