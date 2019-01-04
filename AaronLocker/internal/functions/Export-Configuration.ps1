function Export-Configuration
{
<#
	.SYNOPSIS
		Exports the current configuration to file.
	
	.DESCRIPTION
		Exports the current configuration to file.
		Should be executed after each configuration change.
	
	.EXAMPLE
		PS C:\> Export-Configuration
	
		Exports the current configuration to file.
#>
	[CmdletBinding()]
	Param (
	
	)
	
	begin
	{
		$configParent = Split-Path $script:_ConfigPath
		if (-not (Test-Path $configParent))
		{
			$null = New-Item -Path $configParent -ItemType Directory -Force
		}
	}
	process
	{
		$script:config | ConvertTo-Json | Set-Content -Path $script:_ConfigPath -Encoding UTF8
	}
}