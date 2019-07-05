<#
.SYNOPSIS
    Revert AppLocker policy in GPO to "not configured".

.PARAMETER GpoName
    Name of the group policy object to set the AppLocker policy on.

.PARAMETER GpoGuid
    GUID of the group policy object to set the AppLocker policy on.
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
param(
    [Parameter(Mandatory = $true, ParameterSetName='GpoName')]
    [string]
    $GpoName,

    [Parameter(Mandatory = $true, ParameterSetName='GpoGUID')]
    [guid]
    $GpoGUID,

    [string]
    $Server,

	# If set, applies enforcing rules. Otherwise, applies auditing rules.
	[switch]
	$Enforce = $false
)

####################################################################################################
# Ensure the AppLocker assembly is loaded. (Scripts sometimes run into TypeNotFound errors if not.)
####################################################################################################
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

if ($GpoGUID) {
    $Gpo = Get-GPO -Guid $GpoGUID -ErrorAction Stop
} else {
    $Gpo = Get-GPO -Name $GpoName -ErrorAction Stop
}
$Domain = [System.Directoryservices.Activedirectory.Domain]::GetComputerDomain()
$Server = $Domain.DomainControllers[0].Name
if ($PSCmdlet.ShouldProcess($Gpo.DisplayName, "Clear AppLocker policy")) {
    Write-Host "Clearing AppLocker policy on $($Gpo.DisplayName) in domain $($Domain.Name)" -ForegroundColor Cyan
    $AppLockerPolicy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::new()
    Set-AppLockerPolicy -PolicyObject $AppLockerPolicy -Ldap "LDAP://$Server/$($Gpo.Path)"
}
