<#
.SYNOPSIS
Global support functions. Intended to be dot-sourced into other scripts, and not run directly.

.DESCRIPTION
Global support functions. Intended to be dot-sourced into other scripts, and not run directly.

Functions to save XML consistently as Unicode:
  SaveXmlDocAsUnicode([System.Xml.XmlDocument] $xmlDoc, [string] $xmlFilename)
  SaveAppLockerPolicyAsUnicodeXml([Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]$ALPolicy, [string]$xmlFilename)

Functions to create Excel spreadsheets/workbooks:
  CreateExcelApplication()
  ReleaseExcelApplication()
  SelectFirstWorksheet()
  SaveWorkbook([string]$filename)
  AddNewWorksheet([string]$tabname)
  AddWorksheetFromText([string[]]$text, [string]$tabname)
  AddWorksheetFromCsvFile([string]$filename, [string]$tabname, [string]$CrLfEncoded)
  AddWorksheetFromCsvData([string[]]$csv, [string]$tabname, [string]$CrLfEncoded)
  CreateExcelFromCsvFile([string]$filename, [string]$tabname, [string]$CrLfEncoded, [string]$saveAsName)
#>

#pragma once :-)
if (Test-Path("function:\SaveXmlDocAsUnicode"))
{
    return
} 

####################################################################################################
# Ensure the AppLocker assembly is loaded. (Scripts sometimes run into TypeNotFound errors if not.)
####################################################################################################

[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

####################################################################################################
# Global functions to save XML consistently as Unicode
####################################################################################################

# Note that the "#pragma once" thing at the beginning of this file depends on this function name
function SaveXmlDocAsUnicode([System.Xml.XmlDocument] $xmlDoc, [string] $xmlFilename)
{
    $xws = [System.Xml.XmlWriterSettings]::new()
    $xws.Encoding = [System.Text.Encoding]::Unicode
    $xws.Indent = $true
    $xw = [System.Xml.XmlWriter]::Create($xmlFilename, $xws)
    $xmlDoc.Save($xw)
    $xw.Close()
}

function SaveAppLockerPolicyAsUnicodeXml([Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]$ALPolicy, [string]$xmlFilename)
{
    SaveXmlDocAsUnicode -xmlDoc ([xml]($ALPolicy.ToXml())) -xmlFilename $xmlFilename
}

####################################################################################################
# Global functions to create Excel spreadsheets from CSV data
####################################################################################################

# Global variable treated as a singleton class instance, because managing this variable is a PITA otherwise.
# Not intended to be used by anything other than the functions defined below.
$ExcelAppInstance = $null

# Create global instance of Excel application. Call ReleaseExcelApplication when done using it.
function CreateExcelApplication()
{
    Write-Host "Starting Excel..." -ForegroundColor Cyan
    $global:ExcelAppInstance = New-Object -ComObject excel.application
    if ($null -ne $global:ExcelAppInstance)
    {
        $global:ExcelAppInstance.Visible = $true
        return $true
    }
    else
    {
        Write-Error "Apparently Excel is not installed. Can't create an Excel document without it. Exiting..."
        return $false
    }
}

# Release global instance of Excel application. Make sure to call after CreateExcelApplication.
function ReleaseExcelApplication()
{
    Write-Host "Releasing Excel..." -ForegroundColor Cyan
    $dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($global:ExcelAppInstance)
    $global:ExcelAppInstance = $null
}

function SelectFirstWorksheet()
{
    if ($null -eq $global:ExcelAppInstance) { return }
    if ($global:ExcelAppInstance.Workbooks.Count -eq 0) { return }
    $dummy = $global:ExcelAppInstance.Workbooks[1].Sheets(1).Select()
}

function SaveWorkbook([string]$filename)
{
    Write-Host "Saving workbook as `"$filename`"..." -ForegroundColor Cyan
    if ($null -eq $global:ExcelAppInstance) { return }
    if ($global:ExcelAppInstance.Workbooks.Count -eq 0) { return }
    $global:ExcelAppInstance.Workbooks[1].SaveAs($filename)
}

# Add a new named worksheet with the Excel instance created through CreateExcelApplication
function AddNewWorksheet([string]$tabname)
{
    if ($null -eq $global:ExcelAppInstance) { return $null }

    if ($global:ExcelAppInstance.Workbooks.Count -eq 0)
    {
        $workbook = $global:ExcelAppInstance.Workbooks.Add(5)
        $worksheet = $workbook.Sheets(1)
    }
    else
    {
        $workbook = $global:ExcelAppInstance.Workbooks[1]
        $worksheet = $workbook.Worksheets.Add([System.Type]::Missing, $workbook.Worksheets[$workbook.Worksheets.Count])
    }
    if ($tabname.Length -gt 0)
    {
        # Excel limits tab names to 31 characters
        if ($tabname.Length -gt 31)
        {
            $tabname = $tabname.Substring(0, 31)
        }
        $worksheet.Name = $tabname
    }

    $worksheet
}

# Add a new named worksheet from lines of text (not CSV)
# Supports multi-column text; if text has tab characters, splits across cells in the row
# TODO: Add support for more than 26 columns (e.g., AA1, AB1, AA2, ...)
function AddWorksheetFromText([string[]]$text, [string]$tabname)
{
    Write-Host "Populating tab `"$tabname`"..." -ForegroundColor Cyan

    if ($null -eq $global:ExcelAppInstance) { return $null }

    $worksheet = AddNewWorksheet($tabname)
    $worksheet.UsedRange.VerticalAlignment = -4160 # xlTop

    $row = [int]1
    foreach($line in $text)
    {
        $iCol = [int][char]'A'
        $lineparts = $line.Split("`t")
        foreach ( $part in $lineparts )
        {
            $cell = ([char]$iCol).ToString() + $row.ToString()
            $worksheet.Range($cell).FormulaR1C1 = $part
            $iCol++
        }
        $row++
    }

    $dummy = $worksheet.Cells.EntireColumn.AutoFit()

    # Release COM interface references
    $dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet)
}

# Add a new named worksheet from CSV data in the specified file, optionally replacing encoded CrLf with CrLf.
function AddWorksheetFromCsvFile([string]$filename, [string]$tabname, [string]$CrLfEncoded)
{
    Write-Host "Populating tab `"$tabname`"..." -ForegroundColor Cyan

    if ($null -eq $global:ExcelAppInstance) { return $null }

    $worksheet = AddNewWorksheet($tabname)

    ### Build the QueryTables.Add command
    ### QueryTables does the same as when clicking "Data -> From Text" in Excel
    $TxtConnector = ("TEXT;" + $filename)
    $Connector = $worksheet.QueryTables.add($TxtConnector,$worksheet.Range("A1"))
    $query = $worksheet.QueryTables.item($Connector.name)
    $query.TextFileTabDelimiter = $true

    ### Execute & delete the import query
    $dummy = $query.Refresh()
    $query.Delete()

    if ($CrLfEncoded.Length -gt 0)
    {
        # Replace linebreak-replacement sequence in CSV with CRLF.
        $dummy = $worksheet.UsedRange.Replace($CrLfEncoded, "`r`n")
    }

    # Formatting: autofilter, font size, vertical alignment, freeze top row
    $dummy = $worksheet.Cells.AutoFilter()
    $worksheet.Cells.Font.Size = 9.5
    $worksheet.UsedRange.VerticalAlignment = -4160 # xlTop
    $global:ExcelAppInstance.ActiveWindow.SplitColumn = 0
    $global:ExcelAppInstance.ActiveWindow.SplitRow = 1
    $global:ExcelAppInstance.ActiveWindow.FreezePanes = $true
    $global:ExcelAppInstance.ActiveWindow.Zoom = 80

    $dummy = $worksheet.Range("A2").Select()

    # Formatting: autosize column widths, then set maximum width (except on last column)
    $maxWidth = 40
    $maxHeight = 120

    $dummy = $worksheet.Cells.EntireColumn.AutoFit()
    $ix = 1
    # Do this until the next to last column; don't set max width on the last column
    while ( $worksheet.Cells(1, $ix + 1).Text.Length -gt 0)
    {
        $cells = $worksheet.Cells(1, $ix)
        #Write-Host ($cells.Text + "; " + $cells.ColumnWidth)
        if ($cells.ColumnWidth -gt $maxWidth) { $cells.ColumnWidth = $maxWidth }
        $ix++
    }
    
    # Formatting: autosize row heights, then set maximum height (if CrLf replacement on)
    $dummy = $worksheet.Cells.EntireRow.AutoFit()
    # If line breaks added, limit autofit row height to 
    if ($CrLfEncoded.Length -gt 0)
    {
        $ix = 1
        while ( $worksheet.Cells($ix, 1).Text.Length -gt 0)
        {
            $cells = $worksheet.Cells($ix, 1)
            #Write-Host ($ix.ToString() + "; " + $cells.RowHeight)
            if ($cells.RowHeight -gt $maxHeight) { $cells.RowHeight = $maxHeight }
            $ix++
        }
    }

    # Release COM interface references
    $dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($query)
    $dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Connector)
    $dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet)
}

# Add a new named worksheet from in-memory CSV data (string array), optionally replacing encoded CrLf with CrLf.
function AddWorksheetFromCsvData([string[]]$csv, [string]$tabname, [string]$CrLfEncoded)
{
    Write-Host "Preparing data for tab `"$tabname`"..." -ForegroundColor Cyan

    if ($null -eq $global:ExcelAppInstance) { return $null }

    if ($null -ne $csv)
    {
        $OutputEncodingPrevious = $OutputEncoding
        $OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

        $tempfile = [System.IO.Path]::GetTempFileName()

        $csv | Out-File $tempfile -Encoding unicode

        AddWorksheetFromCsvFile -filename $tempfile -tabname $tabname -CrLfEncoded $CrLfEncoded

        Remove-Item $tempfile

        $OutputEncoding = $OutputEncodingPrevious
    }
    else
    {
        $worksheet = AddNewWorksheet -tabname $tabname
        $dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet)
    }
}

# Create a new Excel workbook with one named worksheet containing CSV data from the specified file,
# optionally replacing encoded CrLf with CrLf.
function CreateExcelFromCsvFile([string]$filename, [string]$tabname, [string]$CrLfEncoded, [string]$saveAsName)
{

    if (CreateExcelApplication)
    {
        AddWorksheetFromCsvFile -filename $filename -tabname $tabname -CrLfEncoded $CrLfEncoded
        if ($saveAsName.Length -gt 0)
        {
            SaveWorkbook -filename $saveAsName
        }
        ReleaseExcelApplication
    }
}
