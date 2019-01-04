function Add-ALRulePath
{
<#
	.SYNOPSIS
		Creates an applocker path rule.
	
	.DESCRIPTION
		Creates a rule for applocker that whitelists or blacklists a specific path.
	
		Note: For maximum security, consider avoiding path rules where possible and use publisher rules instead.
	
	.PARAMETER Path
		The path to create the rule for.
	
	.PARAMETER Label
		The label of the rule to set.
		Labels must be unique within a given policy.
	
	.PARAMETER Exceptions
		Any paths within the specified path to exempt from this rule.
		Use this to selectively exclude paths from the outer rule.
		This is typically used for whitelisting paths such as the Windows folder and then excluding any folders users have write access to.
	
	.PARAMETER Description
		A description of what the rule allows or forbids.
	
	.PARAMETER Identity
		SID of the user or group this rule applies to.
		Defaults to the "users" group (that is: The rule affects all processes not run with elevation)
	
	.PARAMETER Id
		Unique ID of the rule specified.
		Highly optional - if left empty, it will be automatically set on policy creation.
	
	.PARAMETER Collection
		The type of item is being allowed or denied to execute.
	
	.PARAMETER Action
		Whether to allow or deny execution.
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.EXAMPLE
		PS C:\> Add-ALRulePath -Path 'C:\Fabrikam\Custom\*' -Label 'Fabrikam - Custom Application'
	
		Creates a whitelist entry for applications executed from the 'C:\Fabrikam\Custom' folder.
		Note: This is a pretty bad idea if regular users have write access to this folder.
	
	.EXAMPLE
		PS C:\> Import-Csv .\pathrules.csv | Add-ALRulePath
	
		Imports all rules stored in the specified csv.
		Note: The csv files needs to have column headers with exactly the same name as this command's parameters in order for this to work.
	
	.EXAMPLE
		PS C:\> Add-ALRulePath -Path 'C:\Fabrikam\Custom\*' -Label 'Fabrikam - Custom Application' -Exceptions 'C:\Fabrikam\Custom\Input\*', 'C:\Fabrikam\Custom\Data\*'
	
		Creates a whitelist entry for applications executed from the 'C:\Fabrikam\Custom' folder.
		The following folders however are explicitly excluded from this exception:
		- C:\Fabrikam\Custom\Input\*
		- C:\Fabrikam\Custom\Data\*
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Path,
		
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('RuleName', 'Name')]
		[string]
		$Label,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$Exceptions,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]
		$Description,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[System.Security.Principal.SecurityIdentifier]
		$Identity = 'S-1-5-32-545',
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[System.Guid]
		$Id = [guid]::Empty,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[Alias('RuleCollection')]
		[AaronLocker.Scope]
		$Collection = 'Default',
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[AaronLocker.Action]
		$Action = 'Allow',
		
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
		if ($policy.Rules.Label -contains $Label)
		{
			Write-Warning "Rule '$Label' already exists, skipping"
			return
		}
		
		Write-Verbose "Adding path rule $label"
		$rule = New-Object AaronLocker.PathRule -Property @{
			Path		   = $Path
			Exceptions	   = $Exceptions
			Label		   = $Label
			Description    = $Description
			UserOrGroupSid = $Identity
			Id			   = $Id
			Collection	   = $Collection
			Action		   = $Action
		}
		if ($rule) { $policy.Rules.Add($rule) }
	}
	end
	{
		Update-PolicyFile -PolicyName $PolicyName
	}
}