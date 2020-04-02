<#
.SYNOPSIS
Compares two AppLocker policies.

TODO: Add an option to get policies from AD GPO.

.DESCRIPTION
Reads two AppLocker policy XML files, canonicalizes and compares the rule information and reports results as tab-delimited CSV, or optionally to an Excel workbook formatted for sorting and filtering.
Output columns are Compare, Rule, Reference, and Comparison.
The "Compare" column is one of the following values:
  "==" if values are the same in both rule sets
  "<->" if values are present in both rule sets but different
  "<--" if the rule exists only in the reference rule set
  "-->" if the rule exists only in the comparison rule set
The "Rule" column is either the name of a rule collection (Exe, Dll, Script, etc.) or information about a specific rule.
The "Reference" column shows data from the ReferencePolicyXML parameter.
The "Comparison" column shows data from the ComparisonPolicyXML parameter.

Where the "Rule" column contains just the name of a rule collection, the Reference and Comparison columns indicate whether rules for that collection are "AuditOnly" or "Enabled" (enforced).

Otherwise, the "Rule" column shows information about a specific rule, including: the file type (e.g., Dll, Exe); rule type (Publisher, Path, Hash); Allow or Deny; user/group SID; and rule-type-specific information.
For Publisher rules, the rule-specific information catenates the publisher, product, and binary name. (Product or binary name might be empty.)
For Path rules, the path is the rule-specific information.
For Hash rules, the source file name is the rule-specific information.

The Reference and Comparison columns show more detailed rule-type-specific information about the rule from the Reference and Comparison rule sets:
For Publisher rules: the low and high version numbers that the rule applies to. If the Publisher rule includes exceptions, the raw XML is appended.
For Path rules: exceptions to the rule, sorted.
For Hash rules: the hash algorithm and value.

When a rule set contains overlapping rules (e.g., two separate hashes allowed for the same file name), the detailed information is appended into the Reference or Comparison column.

Note that when the -Excel switch is not used, line breaks within the CSV text fields are represented as "^|^".


.PARAMETER ReferencePolicyXML
Path to AppLocker policy XML file.
Use "local" to inspect local policy.
Use "effective" to inspect effective policy.

.PARAMETER ComparisonPolicyXML
Path to AppLocker policy XML file.
Use "local" to inspect local policy.
Use "effective" to inspect effective policy.

.PARAMETER DifferencesOnly
If this optional switch is specified, entries that are in both sets and are identical are not reported.

.PARAMETER Excel
If this optional switch is specified, outputs to a formatted Excel rather than tab-delimited CSV text to the pipeline. Note that when the -Excel switch is not used, line breaks within the CSV text fields are represented as "^|^".

.PARAMETER GridView
If this optional switch is specified, outputs to a PowerShell GridView (note that line breaks within the CSV text fields are represented as "^|^").

.EXAMPLE
.\Compare-Policies.ps1 local effective -DifferencesOnly
Compare local policy against effective policy and report only the differences.
#>


param(
    # path to XML file containing AppLocker policy
    [parameter(Mandatory=$true)]
    [String]
    $ReferencePolicyXML,

    # path to XML file containing AppLocker policy
    [parameter(Mandatory=$true)]
    [String]
    $ComparisonPolicyXML,

    # Don't report items that are the same in both sets.
    [switch]
    $DifferencesOnly,

    # Output to Excel
    [switch]
    $Excel,

    # Output to GridView
    [switch]
    $GridView
)

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file.
. $rootDir\Support\Config.ps1

$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

$keySep = " | "
$linebreakSeq = "^|^"
$tab = "`t"

$refname = $compname = [string]::Empty

# Get reference policy from local policy, effective policy, or a named file
if ($ReferencePolicyXML.ToLower() -eq "local")
{
    $ReferencePolicy = [xml](Get-AppLockerPolicy -Local -Xml)
    $refname = "Local Policy"
}
elseif ($ReferencePolicyXML.ToLower() -eq "effective")
{
    $ReferencePolicy = [xml](Get-AppLockerPolicy -Effective -Xml)
    $refname = "Effective Policy"
}
else
{
    $ReferencePolicy = [xml](Get-Content $ReferencePolicyXML)
    $refname = [System.IO.Path]::GetFileNameWithoutExtension($ReferencePolicyXML)
}

# Get comparison policy from local policy, effective policy, or a named file
if ($ComparisonPolicyXML.ToLower() -eq "local")
{
    $ComparisonPolicy = [xml](Get-AppLockerPolicy -Local -Xml)
    $compname = "Local Policy"
}
elseif ($ComparisonPolicyXML.ToLower() -eq "effective")
{
    $ComparisonPolicy = [xml](Get-AppLockerPolicy -Effective -Xml)
    $compname = "Effective Policy"
}
else
{
    $ComparisonPolicy = [xml](Get-Content $ComparisonPolicyXML)
    $compname = [System.IO.Path]::GetFileNameWithoutExtension($ComparisonPolicyXML)
}


# Create CSV headers
[System.Collections.ArrayList]$csv = @()
$csv.Add( "Compare" + $tab + "Rule" + $tab + "Reference ($refname)" + $tab + "Comparison ($compname)" + $tab + "Reference info" + $tab + "Comparison info" ) | Out-Null


function GetNodeKeyAndValue( $fType, $oNode, [ref] $oKey, [ref] $oValue )
{
    $userOrGroup = $oNode.UserOrGroupSid
    $action = $oNode.Action
    $nameAndDescr = ($oNode.Name + $linebreakSeq + $oNode.Description).Replace("`r`n", $linebreakSeq).Replace("`n", $linebreakSeq)
    $oValue.Value = @{ ruleDetail = ""; ruleDoco = $nameAndDescr; }
    switch ( $oNode.LocalName )
    {
        
    "FilePublisherRule"
    {
        $ruletype = "Publisher"
        $condition = $oNode.Conditions.FilePublisherCondition
        $ruleInfo = $condition.PublisherName + $keySep + $condition.ProductName + $keySep + $condition.BinaryName
        $oKey.Value = $fType + $keySep + $ruletype + $keySep + $action + $keySep + $userOrGroup + $keySep + $ruleInfo
        $oValue.Value.ruleDetail = "Ver " + $condition.BinaryVersionRange.LowSection + " to " + $condition.BinaryVersionRange.HighSection
        if ($oNode.Exceptions.InnerXml.Length -gt 0 )
        {
            $oValue.Value.ruleDetail += ("; Exceptions: " + $oNode.Exceptions.InnerXml)
        }
    }
        
    "FilePathRule" 
    {
        $ruletype = "Path"
        $ruleInfo = $oNode.Conditions.FilePathCondition.Path
        # Exceptions in canonical order.
        $exceptions = 
            (
                (
                @($oNode.Exceptions.FilePathCondition.Path) + 
                @($oNode.Exceptions.FilePublisherCondition.BinaryName) +
                @($oNode.Exceptions.FileHashCondition.FileHash.SourceFileName)
                ) | Sort-Object
            ) -join $linebreakSeq
        $oKey.Value = $fType + $keySep + $ruletype + $keySep + $action + $keySep + $userOrGroup + $keySep + $ruleInfo
        $oValue.Value.ruleDetail = $exceptions
    }
        
    "FileHashRule" 
    {
        $ruletype = "Hash"
        $condition = $oNode.Conditions.FileHashCondition.FileHash
        $ruleInfo = $condition.SourceFileName # + "; length = " + $condition.SourceFileLength
        # $exceptions = "" # hash rules don't have exceptions
        $oKey.Value = $fType + $keySep + $ruletype + $keySep + $action + $keySep + $userOrGroup + $keySep + $ruleInfo
        $oValue.Value.ruleDetail = $condition.Type + " " + $condition.Data
    }
        
    default { Write-Warning ("Unexpected/invalid rule type: " + $_.LocalName) }
        
    }
}


<#
    $collections is a hashtable containing information about the rule collections (Exe, Dll, etc.), and whether each is "Audit" or "Enforce".
    Key = filetype
    Value = Two-element array, where the first element is the reference rule set's enforcement type and the second element is the comparison rule set's enforcement type.

    $rules is a hashtable containing information about AppLocker rules.
    Key = information about rule, combining file type (Exe, Dll, Script, etc.), rule type (Publisher, Path, or Hash), and rule-specific information (see GetNodeKeyAndValue).
    Value = Two-element array, where first element is rule information from the reference rule set, and the second element is from the comparison rule set.
#>
$collections = @{}
$rules = @{}

<#
For both collections, key is a string, value is a two-element array, where element 0 is the reference data and element 1 is the comparison data
When adding a new item, create a new two-element array to set as the value, with either 0 or 1 containing data.
#>


$ReferencePolicy.AppLockerPolicy.RuleCollection | foreach {
    $filetype = $_.Type
    $enforce = $_.EnforcementMode

    <#
    $collections is being newly populated here; value is two-element array in which the reference policy provides data for the first element, and
    the second element is initially empty
    #>
    $collVal = @{ ruleDetail = $enforce; }, $null
    $collections.Add($filetype, $collVal)

    if ($_.ChildNodes.Count -eq 0)
    {
    }
    else
    {
        $_.ChildNodes | foreach {

            $childNode = $_
            $oKey = [ref]""
            $oValue = [ref]""
            GetNodeKeyAndValue $filetype $childNode $oKey $oValue

            # If the reference set already contains this key, see whether the value is a duplicate or a differing value
            # If duplicate, ignore it. If it's different, append it to the existing value
            if ($rules.ContainsKey($oKey.Value))
            {
                $existingVal = $rules[$oKey.Value][0]
                if ($existingVal.ruleDetail -ne $oValue.Value.ruleDetail)
                {
                    $rules[$oKey.Value][0].ruleDetail += ($linebreakSeq + $oValue.Value.ruleDetail)
                }
                if ($existingVal.ruleDoco -ne $oValue.Value.ruleDoco)
                {
                    $rules[$oKey.Value][0].ruleDoco += ($linebreakSeq + $oValue.Value.ruleDoco)
                }
            }
            else
            {
                $ruleVal = $oValue.Value, $null
                $rules.Add($oKey.Value, $ruleVal)
            }
        }
    }
}

$ComparisonPolicy.AppLockerPolicy.RuleCollection | foreach {
    $filetype = $_.Type
    $enforce = $_.EnforcementMode

    # If $collections already has this file type, add to the existing value array; otherwise create a new entry with a new two-element array, populating the second element of that array
    if ($collections.ContainsKey($filetype))
    {
        $collections[$filetype][1] = @{ ruleDetail = $enforce; }
    }
    else
    {
        $collVal = $null, @{ ruleDetail = $enforce }
        $collections.Add($filetype, $collVal)
    }

    # Then do child nodes...
    if ($_.ChildNodes.Count -eq 0)
    {
    }
    else
    {
        $_.ChildNodes | foreach {

            $childNode = $_
            $oKey = [ref]""
            $oValue = [ref]""
            GetNodeKeyAndValue $filetype $childNode $oKey $oValue

            if ($rules.ContainsKey($oKey.Value))
            {
                # If there's already data in the second element, see whether it's a duplicate. If it's a duplicate, ignore; if it's a differing value, append it to the existing value
                $existingVal = $rules[$oKey.Value][1]
                if ($existingVal -eq $null)
                {
                    $rules[$oKey.Value][1] = $oValue.Value
                }
                else
                {
                    if ($existingVal.ruleDetail -ne $oValue.Value.ruleDetail)
                    {
                        $rules[$oKey.Value][1].ruleDetail += ($linebreakSeq + $oValue.Value.ruleDetail)
                    }
                    if ($existingVal.ruleDoco -ne $oValue.Value.ruleDoco)
                    {
                        $rules[$oKey.Value][1].ruleDoco   += ($linebreakSeq + $oValue.Value.ruleDoco)
                    }
                }
            }
            else
            {
                $ruleVal = $null, $oValue.Value
                $rules.Add($oKey.Value, $ruleVal)
            }
        }
    }

}


function ShowKeyValCompare($key, $val)
{
    # Assume that if the key is present, then one or both of val0 and val1 is present
    if ($null -eq $val[0])
    {
        "-->" + $tab + $key + $tab + ""                 + $tab + $val[1].ruleDetail + $tab + ""               + $tab + $val[1].ruleDoco
    }
    elseif ($null -eq $val[1])
    {
        "<--" + $tab + $key + $tab + $val[0].ruleDetail + $tab + ""                 + $tab + $val[0].ruleDoco + $tab
    }
    else
    {   # Canonicalize/sort before performing comparison so that the same items in a different order doesn't report as a difference
        # TODO: re-sort ruleDoco so that its items still correspond to the sorted ruleDetail - not just a simple alpha sort though.
        $val0RuleDetail = ($val[0].ruleDetail.Replace($linebreakSeq, "`n").Split("`n") | Sort-Object) -join $linebreakSeq
        $val1RuleDetail = ($val[1].ruleDetail.Replace($linebreakSeq, "`n").Split("`n") | Sort-Object) -join $linebreakSeq
        if ($val0RuleDetail -eq $val1RuleDetail)
        {
            if (!$DifferencesOnly)
            {
                "=="  + $tab + $key + $tab + $val0RuleDetail + $tab + $val1RuleDetail + $tab + $val[0].ruleDoco + $tab + $val[1].ruleDoco
            }
        }
        else
        {
            "<->"  + $tab + $key + $tab + $val0RuleDetail + $tab + $val1RuleDetail + $tab + $val[0].ruleDoco + $tab + $val[1].ruleDoco
        }
    }
}


# Output everything in order

$csv.AddRange( @(
    $collections.Keys | Sort-Object | foreach {
        ShowKeyValCompare $_ $collections[$_]
    }
    )
)
$csv.AddRange( @(
    $rules.Keys | Sort-Object | foreach {
        ShowKeyValCompare $_ $rules[$_]
    }
    )
)

if ($Excel)
{
    if (CreateExcelApplication)
    {
        AddWorksheetFromCsvData -csv $csv -tabname "$refname vs $compname" -CrLfEncoded $linebreakSeq
        ReleaseExcelApplication
    }
}
elseif ($GridView)
{
    $csv | ConvertFrom-Csv -Delimiter "`t" | Out-GridView -Title $MyInvocation.MyCommand.Name
}
else
{
    # Just output the CSV raw
    $csv
}

$OutputEncoding = $OutputEncodingPrevious

