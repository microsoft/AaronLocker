<#
.SYNOPSIS
Set the most-recently generated AppLocker policy on AD Group Policy.

.DESCRIPTION
Applies the most recent generated "Audit" or "Enforce" rules to a Group Policy object.
Applies the "Audit" rules by default; to apply the "Enforce" rules, use the
-Enforce switch.

.PARAMETER GpoName
Name of the group policy object to set the AppLocker policy on.

.PARAMETER GpoGuid
GUID of the group policy object to set the AppLocker policy on.

.PARAMETER Enforce
If this switch is set, this script applies the "Enforce" rules to Group Policy object.
If this switch is $false, this script applies the "Audit" rules to Group
Policy object.

#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact="High")]
param(
    [Parameter(Mandatory = $true, ParameterSetName='GpoName')]
    [string]
    $GpoName,

    [Parameter(Mandatory = $true, ParameterSetName='GpoGUID')]
    [guid]
    $GpoGUID,

    # If set, applies enforcing rules. Otherwise, applies auditing rules.
    [switch]
    $Enforce = $false
)

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path) + "\.."

# Dot-source the config file.
. $rootDir\Support\Config.ps1

if ($Enforce) {
    $policyFile = RulesFileEnforceLatest
} else {
    $policyFile = RulesFileAuditLatest
}

if ($null -eq $policyFile) {
    Write-Error "No policy file found"
} else {
    if ($GpoGUID) {
        $Gpo = Get-GPO -Guid $GpoGUID -ErrorAction Stop
    } else {
        $Gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    }
    $Domain = [System.Directoryservices.Activedirectory.Domain]::GetComputerDomain()
    $Server = $Domain.DomainControllers[0].Name
    if ($PSCmdlet.ShouldProcess($Gpo.DisplayName, "Set AppLocker policy using $policyFile")) {
        Write-Host "Applying $policyFile to $($Gpo.DisplayName) in domain $($Domain.Name)" -ForegroundColor Cyan
        Set-AppLockerPolicy -XmlPolicy $policyFile -Ldap "LDAP://$Server/$($Gpo.Path)"
    }
}
