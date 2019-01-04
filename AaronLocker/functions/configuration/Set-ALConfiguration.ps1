function Set-ALConfiguration
{
<#
	.SYNOPSIS
		Command that controls the settings of this module.
	
	.DESCRIPTION
		Command that controls the settings of this module.
		Use this to register required resources or tune the module's behavior.
		
		Settings applied here will be persisted across multiple sessions for the current user.
	
	.PARAMETER PathAccessChk
		The path to where AccessChk.exe is stored.
		This sysinternals application is critical to commands enumerating access.
		It can be downloaded from sysinternals.com
	
	.PARAMETER AddKnownAdmins
		Users to add to the list of known administrator accounts.
		Used in commands that take administrative privileges into account.
	
	.PARAMETER RemoveKnownAdmins
		Users to remove from the list of known administrator accounts.
		Used in commands that take administrative privileges into account.
	
	.PARAMETER ActivePolicy
		Change the set of active AppLocker rules worked upon.
		Generally not directly configured. Use Set-ALActivePolicy to update this setting.
	
	.EXAMPLE
		PS C:\> Set-ALConfiguration -PathAccessChk "C:\Program Files\Sysinternals\AccessChk.exe"
		
		Configures the module to look for the AccessChk application in "C:\Program Files\Sysinternals\AccessChk.exe"
#>
	[CmdletBinding()]
	param (
		[string]
		$PathAccessChk,
		
		[string[]]
		$AddKnownAdmins,
		
		[string[]]
		$RemoveKnownAdmins,
		
		[ValidateScript({ (Get-ALPolicy -PolicyName "*").Name -contains $_ })]
		[string]
		$ActivePolicy
	)
	process
	{
		if ($PSBoundParameters.ContainsKey('PathAccessChk'))
		{
			Write-Verbose "Updating path to AccessChk.exe to: $($PathAccessChk)"
			$script:config.PathAccessChk = $PathAccessChk
		}
		if ($PSBoundParameters.ContainsKey('AddKnownAdmins'))
		{
			Write-Verbose "Adding to known admins: $($AddKnownAdmins -join ", ")"
			$script:config.KnownAdmins = $script:config.KnownAdmins, $AddKnownAdmins | Select-Object -Unique
		}
		if ($PSBoundParameters.ContainsKey('RemoveKnownAdmins'))
		{
			Write-Verbose "Updating path to AccessChk.exe to: $($RemoveKnownAdmins)"
			$script:config.KnownAdmins = $script:config.KnownAdmins | Where-Object { $_ -notin $RemoveKnownAdmins }
		}
		if ($PSBoundParameters.ContainsKey('ActivePolicy'))
		{
			Write-Verbose "Setting the current ruleset to: $($ActivePolicy)"
			$script:config.ActivePolicy = $ActivePolicy
		}
		Export-Configuration
	}
}