function Test-AccessChk
{
<#
	.SYNOPSIS
		Checks, whether AccessChk.exe is present on the system.
	
	.DESCRIPTION
		Checks, whether AccessChk.exe is present on the system.
	
	.EXAMPLE
		PS C:\> Test-AchessChk
	
		Checks, whether AccessChk.exe is present on the system.
#>
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		if ($script:config.PathAccessChk -and (Test-Path $script:config.PathAccessChk))
		{
			return $true
		}
		if ($command = Get-Command AccessChk.exe -ErrorAction Ignore)
		{
			$script:config.PathAccessChk = $command.Source
			Export-Configuration
			return $true
		}
		return $false
	}
}