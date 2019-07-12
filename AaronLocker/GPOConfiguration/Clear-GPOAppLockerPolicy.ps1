<#
.SYNOPSIS
Revert AD AppLocker GPO policy to "not configured".
Requires administrative rights.

#>

param(
	# If set, clears auditing rules. Otherwise, clears enforcing rules.
	[switch]
	$AuditOnly = $false,


    # Specify to override GPO name in the ADConfig file
    [parameter(Mandatory=$false)]
    [string]
    $GPONameOverride,

    # Specify to override name of domain controller; otherwise determined automatically
    [parameter(Mandatory=$false)]
    [string]
    $DomainControllerOverride
)

####################################################################################################
# Ensure the AppLocker assembly is loaded. (Scripts sometimes run into TypeNotFound errors if not.)
####################################################################################################
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

$GpoConfigRootDir = $PSScriptRoot

# Dot-source the AD customization file.
. $GpoConfigRootDir\SetADConfig.ps1

if (!(DomainIfADJoined))
{
    Write-Warning "This computer is not AD domain-joined. Exiting."
    return
}

# --------------------------------------------------
# Identify GPO to modify
if ($GPONameOverride)
{
    $gpo = Get-GPO -Name $GPONameOverride
}
elseif ($AuditOnly)
{
    $gpo = Get-GPO -Name $DefAuditGPOName
}
else
{
    $gpo = Get-GPO -Name $DefEnforceGPOName
}

if ($null -eq $gpo)
{
    Write-Warning "GPO not found"
    return
}

# --------------------------------------------------
# Clear AppLocker policy in named GPO

$emptyPol = ([Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::new())

#TODO: Reason for getting more than one DC name is so that we can handle certain failure types by trying the next DC. Not implemented yet.
$DCs = @(GetDomainControllerNames)
$DC = $DCs[0]

$LdapPath = "LDAP://$DC/" + $gpo.Path

Write-Verbose "DC = $DC"
Write-Verbose "LdapPath = $LdapPath"

Write-Host ("Clearing AppLocker policy in GPO `"" + $gpo.DisplayName + "`"") -ForegroundColor Cyan
Set-AppLockerPolicy -PolicyObject $emptyPol -Ldap $LdapPath



