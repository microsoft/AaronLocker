function Add-ALRuleSourcePath
{
<#
	.SYNOPSIS
		Adds a custom source path rule to the list of rules to include when generating AppLocker rules.
	
	.DESCRIPTION
		Adds a custom source path rule to the list of rules to include when generating AppLocker rules.
	
		A source path rule is a path rule that - when resolved - scans the path it points to for executables to whitelist.
		It prefers generating publisher rules where able, when failing this, it will instead create file hash rules.
	
	.PARAMETER Label
		Incorporated into rules' names and descriptions.
	
	.PARAMETER Path
		Identifies one or more paths.
		If a path is a directory, rules are generated for the existing files in that directory.
		If a path is to a file, a rule is generated for that file.
	
	.PARAMETER NoRecurse
		If specified, rules are generated only for the files in the specified directory or directories.
		Otherwise, rules are also generated for files in subdirectories of the specified directory or directories.
	
	.PARAMETER EnforceMinVersion
		If specified, generated publisher rules enforce a minimum file version based on the file versions of the observed files.
		Otherwise, the generated rules do not enforce a minimum file version.
	
	.PARAMETER Identity
		SID of the user or group this rule applies to.
		Defaults to the "users" group (that is: The rule affects all processes not run with elevation)
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.EXAMPLE
		PS C:\> Add-ALRuleSourcePath -Label 'powershell' -Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
		
		Creates a path-based rule to allow powershell.exe.
		Note: The chosen file for this example is actually signed and should not be allowed using a path rule.
	
	.EXAMPLE
		PS C:\> & .\path_rules.ps1 | ForEach-Object { [PSCustomObject]$_ } | Add-ALRuleSourcePath
		
		Imports rules defined as hashtables in the specified script.
	
	.EXAMPLE
		PS C:\> Import-Csv .\path_rules.csv | SelectObject Label, @{ N = "Path"; E = { $_.Path.Split(";") }}, @{ N = "NoRecurse"; E = { $_.NoRecurse -eq "True" }}, @{ N = "EnforceMinVersion"; E = { $_.EnforceMinVersion -eq "True" }} | Add-ALRuleSourcePath
		
		Imports rules from a csv file.
		This example assumes from the csv:
		- A "Label" column that is filled out for each entry
		- A "Path(s)" column that is filled out for each entry. It may contain multiple paths, delimited by a ";"
		- Optionally a NoRecurse column, which may have values or may not either. Only "True" will be considered as enabling (casing is being ignored)
		- Optionally a EnforceMinVersion column, which may have values or may not either. Only "True" will be considered as enabling (casing is being ignored)
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('RuleName', 'Name')]
		[string]
		$Label,
		
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('Paths')]
		[string[]]
		$Path,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[switch]
		$NoRecurse,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[switch]
		$EnforceMinVersion,
		
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
		
		if ($policy.Rules.Label -contains $Label)
		{
			Write-Warning "Rule '$Label' already exists, skipping"
			return
		}
		
		Write-Verbose "Adding source path rule $label"
		$rule = New-Object AaronLocker.SourcePathRule -Property @{
			Label	  = $Label
			Paths	  = $Path
			NoRecurse = $NoRecurse.ToBool()
			EnforceMinVersion = $EnforceMinVersion.ToBool()
			UserOrGroupSid = $Identity
		}
		if ($rule) { $policy.Rules.Add($()) }
	}
	end
	{
		Update-PolicyFile -PolicyName $PolicyName
	}
}
