<#
.SYNOPSIS
Turn AppLocker policy into more human-readable CSV.

.DESCRIPTION
Script reads AppLocker policy from local policy, effective policy, or an XML file, and renders it as a tab-delimited CSV that can be pasted into Microsoft Excel, with easy sorting and filtering.

If neither -AppLockerPolicyFile <path> or -Local is specified, the script processes the current computer's effective policy.

If -linebreakSeq is not specified, CRLF and LF sequences in attribute values are replaced with "^|^". The linebreak sequence can be replaced after importing results into Excel (in the Find/Replace dialog, replace the sequence with Ctrl+Shift+J).

.PARAMETER AppLockerPolicyFile
If this optional string parameter is specified, AppLocker policy is read from the specified XML file.

.PARAMETER Local
If this switch is specified, the script processes the current computer's local policy.

.PARAMETER linebreakSeq
If this optional string parameter is specified, CRLF and LF sequences in attribute values are replaced with the specified sequence. "^|^" is the default.

.EXAMPLE

ExportPolicy-ToCsv.ps1 | clip.exe

Renders effective AppLocker policy to tab-delimited CSV and writes that output to the clipboard using the built-in Windows clip.exe utility.
Paste the output directly into an Excel spreadsheet, replace "^|^" with Ctrl+Shift+J, add filtering, freeze the top row, and autosize.

#>

<#
#TODO: Add option to get AppLocker policy from AD GPO
E.g., 
Get-AppLockerPolicy -Domain -LDAP "LDAP://DC13.Contoso.com/CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=Contoso,DC=com" 
Figure out how to tie Get-GPO in with this...

#>

param(
    # Optional: path to XML file containing AppLocker policy
    [parameter(Mandatory=$false)]
    [String]
    $AppLockerPolicyFile,

    # If specified, inspects local AppLocker policy rather than effective policy or an XML file
    [switch]
    $Local = $false,

    # Optional: specify character sequence to replace line breaks
    [parameter(Mandatory=$false)]
    [String]
    $linebreakSeq = "^|^"
)


$tab = "`t"

if ($AppLockerPolicyFile.Length -gt 0)
{
    # Get policy from a file
    $x = [xml](Get-Content $AppLockerPolicyFile)
}
elseif ($Local)
{
    # Inspect local policy
    $x = [xml](Get-AppLockerPolicy -Local -Xml)
}
else
{
    # Inspect effecive policy
    $x = [xml](Get-AppLockerPolicy -Effective -Xml)
}

# CSV Headers
"FileType" + $tab +
"Enforce" + $tab +
"RuleType" + $tab +
"UserOrGroup" + $tab +
"Action" + $tab +
"RuleInfo" + $tab +
"Exceptions" + $tab +
"Name" + $tab +
"Description"


$x.AppLockerPolicy.RuleCollection | ForEach-Object {
    $filetype = $_.Type
    $enforce = $_.EnforcementMode

    if ($_.ChildNodes.Count -eq 0)
    {
        $filetype + $tab +
        $enforce + $tab +
        "N/A" + $tab +
        "N/A" + $tab +
        "N/A" + $tab +
        "N/A" + $tab +
        "N/A" + $tab +
        "N/A" + $tab +
        "N/A"
    }
    else
    {
        $_.ChildNodes | ForEach-Object {

            $childNode = $_
            switch ( $childNode.LocalName )
            {
        
            "FilePublisherRule"
            {
                $ruletype = "Publisher"
                $condition = $childNode.Conditions.FilePublisherCondition
                $ruleInfo = 
                    "Publisher: " + $condition.PublisherName + $linebreakSeq + 
                    "Product: " + $condition.ProductName + $linebreakSeq + 
                    "BinaryName: " + $condition.BinaryName + $linebreakSeq + 
                    "LowVersion: " + $condition.BinaryVersionRange.LowSection + $linebreakSeq +
                    "HighVersion: " + $condition.BinaryVersionRange.HighSection
            }
        
            "FilePathRule" 
            {
                $ruletype = "Path"
                $ruleInfo = $childNode.Conditions.FilePathCondition.Path
            }
        
            "FileHashRule" 
            {
                $ruletype = "Hash"
                $condition = $childNode.Conditions.FileHashCondition.FileHash
                $ruleInfo = $condition.SourceFileName + "; length = " + $condition.SourceFileLength
            }
        
            default { $ruletype = $_.LocalName; $condition = $ruleInfo = [string]::Empty; }
        
            }

            $exceptions = [string]::Empty
            if ($null -ne $childNode.Exceptions)
            {
                # Output exceptions with a designated separator character sequence that can be replaced with line feeds in Excel
                [System.Collections.ArrayList]$arrExceptions = @()
                if ($null -ne $childNode.Exceptions.FilePathCondition)
                {
                    $arrExceptions.Add( "[----- Path exceptions -----]" ) | Out-Null
                    $arrExceptions.AddRange( @($childNode.Exceptions.FilePathCondition.Path | Sort-Object) )
                }
                if ($null -ne $childNode.Exceptions.FilePublisherCondition)
                {
                    $arrExceptions.Add( "[----- Publisher exceptions -----]" ) | Out-Null
                    $arrExceptions.AddRange( @($childNode.Exceptions.FilePublisherCondition | 
                        ForEach-Object {
                            $s = $_.BinaryName + ": " + $_.PublisherName + "; " + $_.ProductName
                            $bvrLow = $_.BinaryVersionRange.LowSection
                            $bvrHigh = $_.BinaryVersionRange.HighSection
                            if ($bvrLow -ne "*" -or $bvrHigh -ne "*") { $s += "; ver " + $bvrLow + " to " + $bvrHigh }
                            $s
                        } | Sort-Object) )
                }
                if ($null -ne $childNode.Exceptions.FileHashCondition)
                {
                    $arrExceptions.Add( "[----- Hash exceptions -----]" ) | Out-Null
                    $arrExceptions.AddRange( @($childNode.Exceptions.FileHashCondition.FileHash | ForEach-Object { $_.SourceFileName + "; length = " + $_.SourceFileLength } | Sort-Object) )
                }
                $exceptions = $arrExceptions -join $linebreakSeq
            }

            # Replace CRLF with line-break replacement string; then replace any left-over LF characters with it.
            $name = $_.Name.Replace("`r`n", $linebreakSeq).Replace("`n", $linebreakSeq)
            $description = $_.Description.Replace("`r`n", $linebreakSeq).Replace("`n", $linebreakSeq)
            # Get user/group name if possible; otherwise show SID. #was: $userOrGroup = $_.UserOrGroupSid
            $oSID = New-Object System.Security.Principal.SecurityIdentifier($_.UserOrGroupSid)
            $oUser = $null
            try { $oUser = $oSID.Translate([System.Security.Principal.NTAccount]) } catch {}
            if ($null -ne $oUser)
            {
                $userOrGroup = $oUser.Value
            }
            else
            {
                $userOrGroup = $_.UserOrGroupSid
            }
            $action = $_.Action

            $filetype + $tab +
            $enforce + $tab +
            $ruletype + $tab +
            $userOrGroup + $tab +
            $action + $tab +
            $ruleInfo + $tab +
            $exceptions + $tab +
            $name + $tab +
            $description
        }
    }
}
