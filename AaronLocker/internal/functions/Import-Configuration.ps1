function Import-Configuration
{
<#
	.SYNOPSIS
		Imports the module configuration from file.
	
	.DESCRIPTION
		Imports the module configuration from file.
		The file is a preconfigured path in appdata, allowing the user to control, how the module operates.
	
	.EXAMPLE
		PS C:\> Import-Configuration
	
		Imports the persisted configuration
#>
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		if (Test-Path $script:_ConfigPath)
		{
			Get-Content -Path $script:_ConfigPath | ConvertFrom-Json
		}
		else
		{
			[pscustomobject]@{
				PathAccessChk = ""
				KnownAdmins   = @()
				OutputPath    = "$($env:USERPROFILE)\Desktop\AaronLocker"
				ActivePolicy = "default"
			}
		}
	}
}