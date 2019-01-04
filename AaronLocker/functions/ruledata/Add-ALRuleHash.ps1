function Add-ALRuleHash
{
<#
	.SYNOPSIS
		Adds a new hash rule to the list of explicit rules to include.
	
	.DESCRIPTION
		Adds a new hash rule to the list of explicit rules to include.
		Use this to include rules generated from other soures, such as event data or gathered from another machine.
	
	.PARAMETER Collection
		The type of item is being allowed to execute.
	
	.PARAMETER Label
		The label for the rule.
		Must be unique from all other rules.
	
	.PARAMETER Description
		A description of what the rule allows.
	
	.PARAMETER Hash
		The hash of the file being allowed.
	
	.PARAMETER FileName
		The name of the file being allowed.
		Just the filename, not its full path.
	
	.PARAMETER SourceFileLength
		Length of the original input file.
		An optional way to increase hash assurance.
	
	.PARAMETER Identity
		SID of the user or group this rule applies to.
		Defaults to the "users" group (that is: The rule affects all processes not run with elevation)
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.EXAMPLE
		PS C:\> Add-ALRuleHash -Collection Exe -Label $Label -Description $description -Hash $hash -FileName 'file.exe'
		
		Explicitly creates a rule for file.exe.
	
	.EXAMPLE
		PS C:\> Import-Csv .\rules.csv | Add-ALRuleHash
		
		Imports all rules stored in the rules.csv file.
		Note: The csv must have collumns with names matching the parameter names for this to work.
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('RuleCollection')]
		[AaronLocker.Scope]
		$Collection = 'Default',
		
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('RuleName', 'Name')]
		[string]
		$Label,
		
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('RuleDesc')]
		[string]
		$Description,
		
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('HashVal')]
		[string]
		$Hash,
		
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$FileName,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[int]
		$SourceFileLength,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[System.Security.Principal.SecurityIdentifier]
		$Identity = 'S-1-5-32-545',
		
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
		if ($Hash -notmatch '^0x[0-9A-F]{64}$')
		{
			Write-ALError -Message "Invalid hash! Please specify a full SHA256 hash (e.g.: '0x67A9B...', 64 hex characters behind the 'x')" -Terminate
		}
		if ($policy.Rules.Label -contains $Label)
		{
			Write-Warning "Rule '$Label' already exists, skipping"
			return
		}
		
		Write-Verbose "Adding rule '$Label'"
		$rule = New-Object AaronLocker.HashRule -Property @{
			Collection	     = $Collection
			Label		     = $Label
			Description	     = $Description
			HashValue	     = $Hash
			FileName		 = $FileName
			SourceFileLength = $SourceFileLength
			UserOrGroupSid   = $Identity
		}
		if ($rule) { $policy.Rules.Add($rule) }
	}
	end
	{
		Update-PolicyFile -PolicyName $PolicyName
	}
}
