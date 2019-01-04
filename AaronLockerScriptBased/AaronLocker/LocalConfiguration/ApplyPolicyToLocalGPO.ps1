
<#
.SYNOPSIS
Applies the most-recently generated AppLocker rules to local Group Policy.

.DESCRIPTION
Applies the most recent generated "Audit" or "Enforce" rules to local Group Policy.
Applies the "Enforce" rules by default; to apply the "Audit" rules, use the -AuditOnly switch.
Requires administrative rights.

.PARAMETER AuditOnly
If this switch is set, this script applies the "Audit" rules to local Group Policy.
If this switch is $false, this script applies the "Enforce" rules to local Group Policy.

#>

param(
	# If set, applies auditing rules. Otherwise, applies enforcing rules.
	[switch]
	$AuditOnly = $false
)

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path) + "\.."

# Dot-source the config file.
. $rootDir\Support\Config.ps1

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
    Write-Error "No policy file found"
}
else
{
    Write-Host "Applying $policyFile" -ForegroundColor Cyan
    Set-AppLockerPolicy -XmlPolicy $policyFile
}

