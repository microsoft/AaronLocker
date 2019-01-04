function Resolve-ALPolicy
{
<#
	.SYNOPSIS
		Helper that resolves an AaronLocker policy name.
	
	.DESCRIPTION
		Helper that resolves an AaronLocker policy name.
		Use this to avoid hardcoding default values into every function.
		Specifically, it avoids having to insert explicit calls to the configuration in every function, making it easier to later apply changes to that.
	
	.PARAMETER PolicyName
		The name to resolve, can be empty string.
	
	.EXAMPLE
		PS C:\> Resolve-ALPolicy -PolicyName $PolicyName
	
		Returns the resulting policy name to use.
#>
	[OutputType([System.String])]
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[string]
		$PolicyName
	)
	
	if (-not $PolicyName) { return $script:config.ActivePolicy }
	
	if ((Get-ALPolicy -PolicyName "*").Name -notcontains $PolicyName)
	{
		Write-ALError -Message "Policy $($PolicyName) not found! Known policies: $((Get-ALPolicy -PolicyName "*").Name -join ',')" -Terminate
	}
	
	return (Get-ALPolicy -PolicyName $PolicyName).Name
}