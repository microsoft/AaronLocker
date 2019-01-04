function Write-ALError
{
<#
	.SYNOPSIS
		Helper function to write an error.
	
	.DESCRIPTION
		Helper function to write an error.
	
	.PARAMETER ErrorRecord
		The error record to pass on.
	
	.PARAMETER Message
		A custom message to insert.
	
	.PARAMETER Terminate
		Make it a terminating exception
	
	.PARAMETER Continue
		Call continue after writing an exception.
	
	.PARAMETER ContinueLabel
		Call continue with a particular label.
	
	.EXAMPLE
		PS C:\> Write-ALError -ErrorRecord $_ -Terminate
		
		Pass on the received exception and selfterminate.
	
	.EXAMPLE
		PS C:\> Write-ALError -Message "Something broke"
		
		Write an error with the specified message.
	
	.EXAMPLE
		PS C:\> Write-ALError -ErrorRecord $_ -Message "Something broke"
		
		Write an error, passing along the original record but overwriting the message
#>
	[CmdletBinding()]
	param (
		[System.Management.Automation.ErrorRecord]
		$ErrorRecord,
		
		[string]
		$Message,
		
		[switch]
		$Terminate,
		
		[switch]
		$Continue,
		
		[string]
		$ContinueLabel
	)
	
	$cmdlet = Get-Variable -Name PSCmdlet -Scope 1 -ValueOnly
	
	if (-not $Message)
	{
		if ($Terminate) { $Cmdlet.ThrowTerminatingError($ErrorRecord) }
		else { $cmdlet.WriteError($ErrorRecord) }
		if ($ContinueLabel -and $Continue) { continue $ContinueLabel }
		if ($Continue) { continue }
		return
	}
	
	if ($ErrorRecord)
	{
		$exception = New-Object System.Exception($Message, $ErrorRecord.Exception)
		$newRecord = New-Object System.Management.Automation.ErrorRecord($exception, $ErrorRecord.FullyQualifiedErrorID, $ErrorRecord.CategoryInfo.Category, $ErrorRecord.TargetObject)
		if ($Terminate) { $Cmdlet.ThrowTerminatingError($ErrorRecord) }
		else { $cmdlet.WriteError($newRecord) }
		if ($ContinueLabel -and $Continue) { continue $ContinueLabel }
		if ($Continue) { continue }
		return
	}
	
	$exception = New-Object System.Exception($Message)
	$newRecord = New-Object System.Management.Automation.ErrorRecord($exception, $Cmdlet.MyInvocation.InvocationName, "NotSpecified", $null)
	if ($Terminate) { $Cmdlet.ThrowTerminatingError($ErrorRecord) }
	else { $cmdlet.WriteError($newRecord) }
	if ($ContinueLabel -and $Continue) { continue $ContinueLabel }
	if ($Continue) { continue }
}