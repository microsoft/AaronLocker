function Get-ALConfiguration
{
<#
	.SYNOPSIS
		Returns all configuration settings stored by AaronLocker.
	
	.DESCRIPTION
		Returns all configuration settings stored by AaronLocker.
	
	.EXAMPLE
		PS C:\> Get-ALConfiguration
	
		Returns all configuration settings stored by AaronLocker.
#>
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		$resultHash = @{
			PSTypeName = 'AaronLocker.Configuration.Settings'
		}
		foreach ($property in $script:config.PSObject.Properties)
		{
			$resultHash[$property.Name] = $property.Value
		}
		[pscustomobject]$resultHash
	}
}