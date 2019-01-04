function Update-PolicyFile
{
<#
	.SYNOPSIS
		Updates the file system state of a policy.
	
	.DESCRIPTION
		Updates the file system state of a policy.
		Used to ensure data is persisted across sessions.
	
	.PARAMETER PolicyName
		The name of the policy to update
	
	.EXAMPLE
		PS C:\> Update-PolicyFile -PolicyName OneDrive
	
		Updates the disk data of the OneDrive policy.
#>
	[CmdletBinding()]
	Param (
		[string]
		$PolicyName
	)
	
	try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
	catch { Write-ALError -ErrorRecord $_ -Terminate }
	
	$script:_PolicyData[$PolicyName] | Export-Clixml -Path "$($script:_RulesFolder)\$($PolicyName).policy.clixml"
}