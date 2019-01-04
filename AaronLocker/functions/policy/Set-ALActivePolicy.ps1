function Set-ALActivePolicy
{
<#
	.SYNOPSIS
		Select the currently active policy
	
	.DESCRIPTION
		Select the currently active policy.
		AaronLocker supports maintaining multiple sets of policies in parallel.
		Use this command to switch the default policy, in order to avoid having to explicitly specify it.
	
	.PARAMETER PolicyName
		The name of the policy to enable.
		Use 'Get-ALPolicy -List' to receive a list of currently available policies.
		Use 'New-ALPolicy' to define a new policy
	
	.PARAMETER Policy
		The policy object to set as active policy
		Generate using 'Get-ALPolicy -List'.
		Foreign policy objects need to be imported first before enablling them as policy object to use.
	
	.EXAMPLE
		PS C:\> Set-ALActivePolicy -PolicyName 'OneDrive'
	
		Switches the currently active policy to the policy named OneDrive.
	
	.EXAMPLE
		PS C:\> Get-ALPOlicy -List OneDrive | Set-ALActivePolicy
	
		Switches the currently active policy to the policy named OneDrive.
#>
	[CmdletBinding(DefaultParameterSetName = 'name')]
	param (
		[Parameter(Mandatory = $true, ParameterSetName = 'name')]
		[string]
		$PolicyName,
		
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'policy')]
		[AaronLocker.Policy]
		$Policy
	)
	
	begin
	{
		# Explicit implementation, since default policy obviously doesn't work here
		if ($PolicyName -and ((Get-ALPolicy -PolicyName "*").Name -notcontains $PolicyName))
		{
			throw "Policy $($PolicyName) not found! Known policies: $((Get-ALPolicy -PolicyName "*").Name -join ',')"
		}
	}
	process
	{
		if ($PolicyName) { Set-ALConfiguration -ActivePolicy $PolicyName }
		else { Set-ALConfiguration -ActivePolicy $Policy.Name }
	}
}