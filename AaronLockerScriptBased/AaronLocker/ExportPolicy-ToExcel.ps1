<#
.SYNOPSIS
Turns AppLocker policy into a more human-readable Excel worksheet.

.DESCRIPTION
The script gets AppLocker policy from one of four sources, imports it into a new Excel instance, and formats it.

The four source options are:
* Current effective policy (default behavior -- use no parameters);
* Current local policy (use -Local switch);
* Exported AppLocker policy in an XML file (use -AppLockerXML parameter with file path);
* Output previously captured from ExportPolicy-ToCsv.ps1 (use -AppLockerCSV with file path);

This script depends on ExportPolicy-ToCsv.ps1, which should be in the Support subdirectory.
It also depends on Microsoft Excel's being installed.

The three command line options (-Local, -AppLockerXML, -AppLockerCSV) are mutually exclusive: only one can be used at a time.

.PARAMETER Local
If this switch is specified, the script processes the computer's local AppLocker policy.
If no parameters are specified or this switch is set to -Local:$false, the script processes the computer's effective AppLocker policy.

.PARAMETER AppLockerXML
If this parameter is specified, AppLocker policy is read from the specified exported XML policy file.

.PARAMETER AppLockerCSV
If this parameter is specified, AppLocker policy is read from the specified CSV file previously created from ExportPolicy-ToCsv.ps1 output.

.PARAMETER SaveWorkbook
If set, saves workbook to same directory as input file with same file name and default Excel file extension.

.EXAMPLE
.\ExportPolicy-ToExcel.ps1 

Generates an Excel worksheet representing the computer's effective AppLocker policy.

.EXAMPLE
.\Support\ExportPolicy-ToCsv.ps1 | Out-File .\AppLocker.csv; .\ExportPolicy-ToExcel.ps1 -AppLockerCSV .\AppLocker.csv

Generates an Excel worksheet representing AppLocker policy previously generated from ExportPolicy-ToCsv.ps1 output.

.EXAMPLE
Get-AppLockerPolicy -Local -Xml | Out-File .\AppLocker.xml; .\ExportPolicy-ToExcel.ps1 -AppLockerXML .\AppLocker.xml

Generates an Excel worksheet representing AppLocker policy exported from a system into an XML file.

#>

#TODO: Add option to get AppLocker policy from AD GPO, if/when ExportPolicy-ToCsv.ps1 adds it.

[CmdletBinding(DefaultParameterSetName="LocalPolicy")]
param(
    # If specified, inspects local AppLocker policy rather than effective policy or an XML file
    [parameter(ParameterSetName="LocalPolicy")]
    [switch]
    $Local = $false,

    # Optional: path to XML file containing AppLocker policy
    [parameter(ParameterSetName="SavedXML")]
    [String]
    $AppLockerXML,

    # If specified, uses CSV previously collected instead of running ExportPolicy-ToCsv.ps1
    [parameter(ParameterSetName="SavedCSV")]
    [String]
    $AppLockerCSV,

    [parameter(ParameterSetName="SavedXML")]
    [parameter(ParameterSetName="SavedCSV")]
    [switch]
    $SaveWorkbook
)

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file.
. $rootDir\Support\Config.ps1

$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode


$tabname = "AppLocker policy"
$filename = $tempfile = $xlFname = [String]::Empty

$linebreakSeq = "^|^"

if ($AppLockerCSV.Length -gt 0)
{
    $filename = $AppLockerCSV
    $tabname = [System.IO.Path]::GetFileName($AppLockerCSV)
    if ($SaveWorkbook)
    {
        $xlFname = [System.IO.Path]::ChangeExtension($AppLockerCSV, ".xlsx")
    }
}
else
{
    $filename = $tempfile = [System.IO.Path]::GetTempFileName()

    if ($AppLockerXML.Length -gt 0)
    {
        & $ps1_ExportPolicyToCSV -AppLockerPolicyFile $AppLockerXML -linebreakSeq $linebreakSeq | Out-File $tempfile -Encoding unicode
        $tabname = [System.IO.Path]::GetFileNameWithoutExtension($AppLockerXML)
        if ($SaveWorkbook)
        {
            $xlFname = [System.IO.Path]::ChangeExtension($AppLockerXML, ".xlsx")
        }
    }
    else
    {
        & $ps1_ExportPolicyToCSV -Local:$Local -linebreakSeq $linebreakSeq | Out-File $tempfile -Encoding unicode
        if ($Local)
        {
            $tabname = "AppLocker policy - Local"
        }
        else
        {
            $tabname = "AppLocker policy - Effective"
        }
    }
}

if ($xlFname.Length -gt 0)
{
    # Ensure absolute path
    if (!([System.IO.Path]::IsPathRooted($xlFname)))
    {
        $xlFname = [System.IO.Path]::Combine((Get-Location).Path, $xlFname)
    }
}

CreateExcelFromCsvFile $filename $tabname $linebreakSeq $xlFname

# Delete the temp file
if ($tempfile.Length -gt 0) { Remove-Item $tempfile }

$OutputEncoding = $OutputEncodingPrevious
