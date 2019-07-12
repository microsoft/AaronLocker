<#
.SYNOPSIS
Reporting for "AaronLocker" security groups.

TODO: Separate script for managing groups, adding to groups, removing from groups, replacing content of groups, possibly with duplicate validation/correction built in.
TODO: Add -Excel option which creates a workbook with all three reports on separate tabs.

.DESCRIPTION
In Group Policy-managed environments, "AaronLocker" recommends defining three security groups to control access to the Group Policy Objects containing AppLocker policies.
Each managed computer should be in zero or one of those groups, and never in more than one.
This script provides three report types, each of which outputs tab-delimited CSV:
* DuplicateMemberships to report any computers that are in more than one of the security groups.
* ByComputerName reports a sorted list of all computers that are members of any of the groups, and the group or groups each is in.
* ByGroupName reports a sorted list of the security groups and the computers that are in each.
You must pick one of the report types.
Optionally, you can also override the default security group names.

.PARAMETER DuplicateMemberships
By default this script always outputs reports of computers that are in more than one of the security groups.
If this switch is specified, the report does NOT include the reporting of duplicates.

.PARAMETER ByComputerName
If this switch is specified, report also outputs a sorted list of all the computers that are in one or more "AaronLocker" security groups and the groups they are in.

.PARAMETER ByGroupName
If this switch is specified, report also outputs each "AaronLocker" security group and its membership, sorted.

.PARAMETER AuditGroupNameOverride
Optional parameter to specify the name of the "audit" security group (default = "AppLocker-Audit").

.PARAMETER EnforceGroupNameOverride
Optional parameter to specify the name of the "enforce" security group (default = "AppLocker-Enforce").

.PARAMETER ExemptGroupNameOverride
Optional parameter to specify the name of the "exempt" security group (default = "AppLocker-Exempt").

.EXAMPLE
[ put good examples here, including one that pipes output to clip.exe ]
#>

param(
    [parameter(ParameterSetName="DuplicateMemberships", Mandatory=$true)]
    [switch]
    $DuplicateMemberships,

    [parameter(ParameterSetName="ByComputerName", Mandatory=$true)]
    [switch]
    $ByComputerName,

    [parameter(ParameterSetName="ByGroupName", Mandatory=$true)]
    [switch]
    $ByGroupName,

    [parameter(Mandatory=$false)]
    [string]
    $AuditGroupNameOverride,

    [parameter(Mandatory=$false)]
    [string]
    $EnforceGroupNameOverride,

    [parameter(Mandatory=$false)]
    [string]
    $ExemptGroupNameOverride
)

# --------------------------------------------------

$GpoConfigRootDir = $PSScriptRoot

# Dot-source the AD customization file.
. $GpoConfigRootDir\SetADConfig.ps1

if (!(DomainIfADJoined))
{
    Write-Warning "This computer is not AD domain-joined. Exiting."
    return
}

# --------------------------------------------------
# Establish group names to look up

$AuditGroupName = $DefAuditGroupName
$EnforceGroupName = $DefEnforceGroupName
$ExemptGroupName = $DefExemptGroupName

if ($AuditGroupNameOverride -ne [string]::Empty)
{
    $AuditGroupName = $AuditGroupNameOverride
}

if ($EnforceGroupNameOverride -ne [string]::Empty)
{
    $EnforceGroupName = $EnforceGroupNameOverride
}

if ($ExemptGroupNameOverride -ne [string]::Empty)
{
    $ExemptGroupName = $ExemptGroupNameOverride
}

# Validate the groups' existence
$AuditGroup = $EnforceGroup = $ExemptGroup = $null
$AuditGroup   = Get-ADGroup -Identity $AuditGroupName
$EnforceGroup = Get-ADGroup -Identity $EnforceGroupName
$ExemptGroup  = Get-ADGroup -Identity $ExemptGroupName

if ($null -eq $AuditGroup -or $null -eq $EnforceGroup -or $null -eq $ExemptGroup)
{
    # Error details already displayed
    Write-Error "Fix issues with groups"
    return
}

# --------------------------------------------------
# Get and analyze the groups' memberships

$AuditMembers = @(Get-ADGroupMember -Identity $AuditGroupName)
$EnforceMembers = @(Get-ADGroupMember -Identity $EnforceGroupName)
$ExemptMembers = @(Get-ADGroupMember -Identity $ExemptGroupName)

# Hash table identifying group memberships
$memberships = @{}
# Hash table identifying entities that are in more than one group
$duplicates = @{}

$AuditMembers | ForEach-Object {
    $dn = $_.distinguishedName
    $memberships.Add($dn, "Audit")
}
$EnforceMembers | ForEach-Object {
    $dn = $_.distinguishedName
    if ($memberships.ContainsKey($dn))
    {
        $duplicates.Add($dn, "")
        $memberships[$dn] += ", Enforce"
    }
    else
    {
        $memberships.Add($dn, "Enforce")
    }
}
$ExemptMembers | ForEach-Object {
    $dn = $_.distinguishedName
    if ($memberships.ContainsKey($dn))
    {
        if (!$duplicates.ContainsKey($dn)) { $duplicates.Add($dn, "") }
        $memberships[$dn] += ", Exempt"
    }
    else
    {
        $memberships.Add($dn, "Exempt")
    }
}

#
# Report computers that are in more than one group.
#
if ($DuplicateMemberships)
{
    if ($duplicates.Count -eq 0)
    {
        Write-Output "No computer is in more than one group."
    }
    else
    {
        Write-Output "Computer`tMultiple groups"
        $duplicates.Keys | Sort-Object | ForEach-Object {
            Write-Output ($_ + "`t" + $memberships[$_])
        }
    }
}

#
# List all computers that are in groups(s) ordered by computer name
#
if ($ByComputerName)
{
    Write-Output "Computer`tGroup(s)"
    $memberships.Keys | Sort-Object | ForEach-Object {
        Write-Output ($_ + "`t" + $memberships[$_])
    }
}

#
# List groups and the computers in them
#
if ($ByGroupName)
{
    Write-Output "Group`tComputer"

    #Write-Output ("Members of " + $AuditGroupName)
    $AuditMembers | Sort-Object | ForEach-Object {
        Write-Output ("$AuditGroupName`t" + $_)
    }

    #Write-Output ""
    #Write-Output ("Members of " + $EnforceGroupName)
    $EnforceMembers | Sort-Object | ForEach-Object {
        Write-Output ("$EnforceGroupName`t" + $_)
    }

    #Write-Output ("Members of " + $ExemptGroupName)
    $ExemptMembers | Sort-Object | ForEach-Object {
        Write-Output ("$ExemptGroupName`t" + $_)
    }
}

