<#
.SYNOPSIS
Script used to define hash rules without direct access to the files.

.DESCRIPTION
This script outputs zero or more hashtables containing information to define hash rules.
It supports creating hash rules based on AppLocker event data rather than on direct access to the files.

Each hashtable must have each of the following properties: 
* RuleCollection
* RuleName
* RuleDesc
* HashVal
* FileName

NOTES:
* RuleCollection must be one of "Exe", "Dll", "Script", or "Msi", and is CASE-SENSITIVE.
* HashVal must be "0x" followed by 64 hex digits (SHA256 hash).

Example:

@{
RuleCollection = "Script";
RuleName = "Contoso Products: DoGoodStuff.cmd - HASH RULE";
RuleDesc = "Identified in: %LOCALAPPDATA%\TEMP\DoGoodStuff.cmd";
HashVal  = "0x4CA1CD60FBFBA42C00EA6EA1B56BEFE6AD90FE0EFF58285A75D77B515D864DAE";
FileName = "DoGoodStuff.cmd"
}

#>
