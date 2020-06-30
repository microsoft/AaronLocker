<#
.SYNOPSIS
Defines variables for path names and other configuration settings. Intended to be dot-sourced into other scripts, and not run directly.
Also loads global support functions.

.DESCRIPTION
Defines variables for path names and other configuration settings. Intended to be dot-sourced into other scripts, and not run directly.
Also loads global support functions.

Variable $rootDir must already have been set prior to calling this script.
#>

# Verify that $rootDir has been defined and is an existing directory.
if ($null -eq $rootDir -or !(Test-Path($rootDir)))
{
    Write-Error ('Script error: variable $rootDir is not defined prior to invoking ' + $MyInvocation.MyCommand.Path)
    return
}

####### Establish directory paths
$customizationInputsDir = [System.IO.Path]::Combine($rootDir, "CustomizationInputs")
$mergeRulesDynamicDir   = [System.IO.Path]::Combine($rootDir, "MergeRules-Dynamic")
$mergeRulesStaticDir    = [System.IO.Path]::Combine($rootDir, "MergeRules-Static")
$outputsDir             = [System.IO.Path]::Combine($rootDir, "Outputs")
$supportDir             = [System.IO.Path]::Combine($rootDir, "Support")
$scanResultsDir         = [System.IO.Path]::Combine($rootDir, "ScanResults")

####### INPUTS

# Script inputs
$ps1_GetExeFilesToDenyList     = [System.IO.Path]::Combine($customizationInputsDir, "GetExeFilesToDenyList.ps1")
$ps1_GetSafePathsToAllow        = [System.IO.Path]::Combine($customizationInputsDir, "GetSafePathsToAllow.ps1")
$ps1_UnsafePathsToBuildRulesFor = [System.IO.Path]::Combine($customizationInputsDir, "UnsafePathsToBuildRulesFor.ps1")
$fname_TrustedSigners           = "TrustedSigners.ps1"
$ps1_TrustedSigners             = [System.IO.Path]::Combine($customizationInputsDir, $fname_TrustedSigners)
$ps1_TrustedSignersWDAC         = [System.IO.Path]::Combine($customizationInputsDir, "WDACTrustedSigners.ps1")
$ps1_HashRuleData               = [System.IO.Path]::Combine($customizationInputsDir, "HashRuleData.ps1")
$ps1_KnownAdmins                = [System.IO.Path]::Combine($customizationInputsDir, "KnownAdmins.ps1")
$ps1_CreatePoliciesAppLocker    = [System.IO.Path]::Combine($rootDir, "Create-Policies-AppLocker.ps1")
$ps1_CreatePoliciesWDAC         = [System.IO.Path]::Combine($rootDir, "Create-Policies-WDAC.ps1")

# File prefixes for AppLocker and WDAC
$rulesFileBase = "AppLockerRules-"
$WDACrulesFileBase = "WDACRules-"
# Path to results from scanning files listed in GetExeFilesToDenyList
$ExeDenyListData = [System.IO.Path]::Combine($scanResultsDir, "ExeDenyListData.txt")
# Paths to "full" results of all user-writable directories under Windir and the ProgramFiles directories.
# Written to when Rescan enabled; used to create the next set of files
$windirFullXml    = [System.IO.Path]::Combine($scanResultsDir, "Writable_Full_windir.xml")
$PfFullXml        = [System.IO.Path]::Combine($scanResultsDir, "Writable_Full_PF.xml")
$Pf86FullXml      = [System.IO.Path]::Combine($scanResultsDir, "Writable_Full_PF86.xml")
# Paths to filtered results with redundancies removed.
# Written to when Rescan enabled; read from when building rule set.
$windirTxt        = [System.IO.Path]::Combine($scanResultsDir, "Writable_windir.txt")
$PfTxt            = [System.IO.Path]::Combine($scanResultsDir, "Writable_PF.txt")
$Pf86Txt          = [System.IO.Path]::Combine($scanResultsDir, "Writable_PF86.txt")


####### SUPPORT
$defRulesXml                                 = [System.IO.Path]::Combine($supportDir, "DefaultRulesWithPlaceholders.xml")
$ps1_EnumWritableDirs                        = [System.IO.Path]::Combine($supportDir, "Enum-WritableDirs.ps1")
$ps1_BuildRulesForFilesInWritableDirectories = [System.IO.Path]::Combine($supportDir, "BuildRulesForFilesInWritableDirectories.ps1")
$ps1_ExportPolicyToCSV                       = [System.IO.Path]::Combine($supportDir, "ExportPolicy-ToCsv.ps1")
$ps1_ExportPolicyToExcel                     = [System.IO.Path]::Combine($rootDir,    "ExportPolicy-ToExcel.ps1")


####### OUTPUTS AND TIMESTAMPS
# Paths to result files containing AppLocker policy rules.
# Policy rules file have timestamp embedded into file name so previous ones don't get overwritten and so that alphabetic sort shows which is newest.
# Example filenames:
#    AppLockerRules-20180518-1151-Audit.xml
#    AppLockerRules-20180518-1151-Enforce.xml
$dtNow = [datetime]::Now
$strRuleDocTimestamp = $dtNow.ToString("yyyy-MM-dd HH:mm")
$strFnameTimestamp = $dtNow.ToString("yyyyMMdd-HHmm")
$strTimestampForHashRule = $dtNow.ToString("yyyyMMddHHmmss")
$rulesFileAuditSuffix = "-Audit.xml"
$rulesFileEnforceSuffix = "-Enforce.xml"
$rulesFileAuditNew   = [System.IO.Path]::Combine($outputsDir, $rulesFileBase + $strFnameTimestamp + $rulesFileAuditSuffix)
$rulesFileEnforceNew = [System.IO.Path]::Combine($outputsDir, $rulesFileBase + $strFnameTimestamp + $rulesFileEnforceSuffix)
$WDACrulesFileAuditNew   = [System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + $strFnameTimestamp + "-Allow" + $rulesFileAuditSuffix)
$WDACrulesFileEnforceNew = [System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + $strFnameTimestamp + "-Allow" +  $rulesFileEnforceSuffix)
$WDACDenyrulesFileAuditNew   = [System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + $strFnameTimestamp + "-Deny" + $rulesFileAuditSuffix)
$WDACDenyrulesFileEnforceNew = [System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + $strFnameTimestamp + "-Deny" + $rulesFileEnforceSuffix)
# Get latest audit and enforce policy files, or $null if none found.
function RulesFileAuditLatest()
{
    Get-ChildItem $([System.IO.Path]::Combine($outputsDir, $rulesFileBase + "*" + $rulesFileAuditSuffix)) | foreach { $_.FullName } | Sort-Object | Select-Object -Last 1
}
function RulesFileEnforceLatest()
{
    Get-ChildItem $([System.IO.Path]::Combine($outputsDir, $rulesFileBase + "*" + $rulesFileEnforceSuffix)) | foreach { $_.FullName } | Sort-Object | Select-Object -Last 1
}
function WDACRulesFileAuditLatest()
{
    Get-ChildItem $([System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + "*" + $rulesFileAuditSuffix)) -Exclude *DENY* | foreach { $_.FullName } | Sort-Object | Select-Object -Last 1
}
function WDACRulesFileEnforceLatest()
{
    Get-ChildItem $([System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + "*" + $rulesFileEnforceSuffix)) -Exclude *DENY* | foreach { $_.FullName } | Sort-Object | Select-Object -Last 1
}
function WDACDenyRulesFileAuditLatest()
{
    Get-ChildItem $([System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + "*Deny" + $rulesFileAuditSuffix)) | foreach { $_.FullName } | Sort-Object | Select-Object -Last 1
}
function WDACDenyRulesFileEnforceLatest()
{
    Get-ChildItem $([System.IO.Path]::Combine($outputsDir, $WDACrulesFileBase + "*Deny" + $rulesFileEnforceSuffix)) | foreach { $_.FullName } | Sort-Object | Select-Object -Last 1
}


####### GLOBAL FUNCTIONS
# Incorporate global support functions
. $rootDir\Support\SupportFunctions.ps1
