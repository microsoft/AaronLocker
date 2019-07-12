<#
.SYNOPSIS
Applies the most-recently generated AppLocker rules to AD Group Policy.

.DESCRIPTION
Applies the most recent generated "Audit" or "Enforce" rules to AD Group Policy.
Applies the "Enforce" rules by default; to apply the "Audit" rules, use the -AuditOnly switch.
Requires administrative rights.

.PARAMETER AuditOnly
If this switch is set, this script applies the "Audit" rules to AD Group Policy.
If this switch is $false, this script applies the "Enforce" rules to AD Group Policy.

#>

param(
	# If set, applies auditing rules. Otherwise, applies enforcing rules.
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

# Parent directory of this script
$rootDir = [System.IO.Path]::GetDirectoryName($PSScriptRoot)
# Dot-source the config file and support functions to pick up policy file to apply.
. $rootDir\Support\Config.ps1

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
# Get AppLocker policy file to apply to GPO
if ($AuditOnly)
{
    $policyFile = RulesFileAuditLatest
}
else
{
    $policyFile = RulesFileEnforceLatest
}

if ($null -eq $policyFile)
{
    Write-Warning "No policy file found"
    return
}

# --------------------------------------------------
# Set AppLocker policy in named GPO with latest policy file

#TODO: Reason for getting more than one DC name is so that we can handle certain failure types by trying the next DC. Not implemented yet.
$DCs = @(GetDomainControllerNames)
$DC = $DCs[0]

$LdapPath = "LDAP://$DC/" + $gpo.Path

Write-Verbose "DC = $DC"
Write-Verbose "LdapPath = $LdapPath"

Write-Host ("Applying `"$policyFile`" to GPO `"" + $gpo.DisplayName + "`"") -ForegroundColor Cyan
Set-AppLockerPolicy -XmlPolicy $policyFile -Ldap $LdapPath


