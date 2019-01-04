function Add-ALRulePublisher
{
<#
	.SYNOPSIS
		Adds a publisher rule to the list of explicitly included rules.
	
	.DESCRIPTION
		Adds a publisher rule to the list of explicitly included rules.
		These will become part of the output generated from New-ALPolicyScan.
	
	.PARAMETER Label
		Text that is incorporated into the rule name and description.
	
	.PARAMETER PublisherName
		Literal canonical name identifying a publisher to trust.
	
	.PARAMETER ProductName
		Restrict trust just to that product by that publisher.
	
	.PARAMETER BinaryName
		Restrict trust to a specific internal file name.
	
	.PARAMETER FileVersion
		The minimum allowed file version for the specified file.
	
	.PARAMETER Collection
		The type of item is being allowed or denied to execute.
	
	.PARAMETER Exemplar
		Path to a signed file, the publisher to trust is extracted from that signature.
	
	.PARAMETER UseProduct
		Whether to restrict publisher trust only to that file's product name.
	
	.PARAMETER Description
		A description of what the rule allows or forbids.
	
	.PARAMETER Identity
		SID of the user or group this rule applies to.
		Defaults to the "users" group (that is: The rule affects all processes not run with elevation)
	
	.PARAMETER Id
		Unique ID of the rule specified.
		Highly optional - if left empty, it will be automatically set on policy creation.
	
	.PARAMETER Action
		Whether to allow or deny execution.
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.EXAMPLE
		PS C:\> Add-ALRulePublisher -Label 'Trust all Contoso' -PublisherName 'O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US'
		
		Trust everything by a specific publisher
	
	.EXAMPLE
		PS C:\> Add-ALRulePublisher -Label 'Trust all Contoso DLLs' -PublisherName 'O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US' -Collection Dll
		
		Trust all DLLs by a specific publisher
	
	.EXAMPLE
		PS C:\> Add-ALRulePublisher -Label 'Trust all CUSTOMAPP files published by Contoso' -PublisherName 'O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US' -ProductName 'CUSTOMAPP'
		
		Trust a specific product published by a specific publisher
	
	.EXAMPLE
		PS C:\> Add-ALRulePublisher -Label 'Trust Contoso's SAMPLE.DLL in CUSTOMAPP' -PublisherName 'O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US' -ProductName 'CUSTOMAPP' -BinaryName 'SAMPLE.DLL' -FileVersion '10.0.15063.0' -Collection 'Dll'
		
		Trust a specific version of a specific signed file by a specific publisher/product
	
	.EXAMPLE
		PS C:\> Add-ALRulePublisher -Label 'Trust the publisher of Autoruns.exe' -Exemplar 'C:\Program Files\Sysinternals\Autoruns.exe'
		
		Trust everything signed by the same publisher as the exemplar file (Autoruns.exe)
	
	.EXAMPLE
		PS C:\> Add-ALRulePublisher -Label 'Trust everything with the same publisher and product as LuaBuglight.exe' -Exemplar 'C:\Program Files\Utils\LuaBuglight.exe' -UseProduct
		
		Trust everything with the same publisher and product as the exemplar file (LuaBuglight.exe)
	
	.EXAMPLE
		PS C:\> Import-Csv .\rules.csv | Add-ALRulePulisher
		
		Adds all rules stored in rules.csv.
		Note: The Csv must contain column names matching the parameters of this command.
#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[Alias('RuleName', 'Name')]
		[string]
		$Label,
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Explicit', Mandatory = $true)]
		[string]
		$PublisherName,
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Explicit')]
		[string]
		$ProductName,
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Explicit')]
		[string]
		$BinaryName,
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Explicit')]
		[Version]
		$FileVersion,
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Explicit')]
		[Alias('RuleCollection')]
		[AaronLocker.Scope]
		$Collection = 'Default',
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Reference', Mandatory = $true)]
		[string]
		$Exemplar,
		
		[Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Reference')]
		[switch]
		$UseProduct,
		
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
		
		$ruleHash = @{
			Label		   = $Label
			Description    = $Description
			UserOrGroupSid = $Identity
			Id			   = $Id
			Collection	   = $Collection
			Action		   = $Action
		}
		if ($PublisherName) { $ruleHash["PublisherName"] = $PublisherName }
		if ($ProductName) { $ruleHash["ProductName"] = $ProductName }
		if ($BinaryName) { $ruleHash["BinaryName"] = $BinaryName }
		if ($FileVersion) { $ruleHash["FileVersion"] = $FileVersion }
		if ($Collection) { $ruleHash["RuleCollection"] = $Collection }
		if ($Exemplar) { $ruleHash["Exemplar"] = $Exemplar }
		if ($UseProduct) { $ruleHash["UseProduct"] = $UseProduct }
		
		Write-Verbose "Adding publisher rule $label"
		$rule = New-Object AaronLocker.PublisherRule -Property $ruleHash
		if ($rule) { $policy.Rules.Add($rule) }
	}
	end
	{
		Update-PolicyFile -PolicyName $PolicyName
	}
}
