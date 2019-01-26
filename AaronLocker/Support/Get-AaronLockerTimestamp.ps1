<#
.SYNOPSIS
Gets custom timestamp field from AaronLocker-generated AppLocker rule set.

.DESCRIPTION
Retrieves an AppLocker policy, and reports the AaronLocker-generated timestamp, if found.

AaronLocker inserts a "timestamp" rule that shows when the rule set was generated and helps associate it with a rule file with the same timestamp.

This script can inspect local policy, effective policy, or an AppLocker policy XML file.

The AaronLocker-generated timestamp is stored in the name and description of an Exe "deny" hash rule with a bogus hash value and
applied to the "CREATOR OWNER" user. Because "CREATOR OWNER" never appears in a user's access token, the rule will never be applied.
The "Deny" and "CREATOR OWNER" attributes make it stand out and easily visible in an AaronLocker rule set.

.PARAMETER Local
If this switch is specified, the script processes the computer's local AppLocker policy.
If no parameters are specified or this switch is set to -Local:$false, the script processes the computer's effective AppLocker policy.

.PARAMETER AppLockerXML
If this parameter is specified, AppLocker policy is read from the specified exported XML policy file.

.EXAMPLE
.\Support\Get-AaronLockerTimestamp.ps1 

Gets the custom timestamp field from the computer's effective AppLocker policy.

#>

[CmdletBinding(DefaultParameterSetName="LocalPolicy")]
param(
    # If specified, inspects local AppLocker policy rather than effective policy or an XML file
    [parameter(ParameterSetName="LocalPolicy")]
    [switch]
    $Local = $false,

    # Optional: path to XML file containing AppLocker policy
    [parameter(ParameterSetName="SavedXML")]
    [String]
    $AppLockerXML
)

if ($AppLockerXML.Length -gt 0)
{
    $xmlPolicy = [xml](Get-Content -Path $AppLockerXML)
}
elseif ($Local)
{
    $xmlPolicy = [xml](Get-AppLockerPolicy -Local -Xml)
}
else
{
    $xmlPolicy = [xml](Get-AppLockerPolicy -Effective -Xml)
}

if ($null -ne $xmlPolicy)
{
    $node = $xmlPolicy.SelectNodes("AppLockerPolicy/RuleCollection[@Type='Exe']/FileHashRule[@UserOrGroupSid='S-1-3-0']")
    if ($null -eq $node -or 0 -eq $node.Count)
    {
        Write-Warning "Policy does not include timestamp"
    }
    else
    {
        $node.Name
    }
}
