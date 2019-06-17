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

Function to determine whether a file is a Win32 EXE, a Win32 DLL, or neither
  IsWin32Executable([string]$filename)

Global variables defining known file extensions
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

####################################################################################################
# Global function to determine whether a file is a Win32 EXE, a Win32 DLL, or neither
####################################################################################################

# Returns "EXE", "DLL", or nothing
function IsWin32Executable([string]$filename)
{

    # sizes, offsets, and values for PE header structures
    Set-Variable sizeofImageDosHeader -Option Constant -Value 64
    Set-Variable sizeofImageNtHeaders64 -Option Constant -Value 264
    Set-Variable offset_e_lfanew -Option Constant -Value 60
    Set-Variable offset_FileHeader -Option Constant -Value 4
    Set-Variable offset_FileHeader_Characteristics -Option Constant -Value 18
    Set-Variable offset_OptionalHeader -Option Constant -Value 24
    Set-Variable offset_OptionalHeader_Subsystem -Option Constant -Value 68
    Set-Variable IMAGE_SUBSYSTEM_WINDOWS_GUI -Option Constant -Value 2
    Set-Variable IMAGE_SUBSYSTEM_WINDOWS_CUI -Option Constant -Value 3


    # Read first 64 bytes (size of IMAGE_DOS_HEADER)
    # Always make sure returned data is an array, even if the file contains exactly one byte
    $bytesImageDosHeader = @(Get-Content -Encoding Byte -TotalCount $sizeofImageDosHeader $filename -ErrorAction SilentlyContinue)
    if ($null -eq $bytesImageDosHeader -or $bytesImageDosHeader.Length -lt $sizeofImageDosHeader)
    {
        Write-Verbose "$filename : Non-existent or unreadable file, or less than $sizeofImageDosHeader bytes."
        #Write-Output ""
        return;
    }

    # Verify that the first two bytes are "MZ"
    $dosSig = "" + [char]($bytesImageDosHeader[0]) + [char]($bytesImageDosHeader[1])
    if ($dosSig -ne "MZ")
    {
        Write-Verbose "$filename : Not a PE file; first two bytes are not MZ."
        #Write-Output ""
        return;
    }

    # Read the IMAGE_DOS_HEADER e_lfanew attribute to determine the offset into the file where the IMAGE_NT_HEADERS begin
    # This line of code adapted from Matt Graeber, http://www.exploit-monday.com/2013/03/ParsingBinaryFileFormatsWithPowerShell.html
    $offsetImageNtHeaders = [Int32]('0x{0}' -f (( $bytesImageDosHeader[ ($offset_e_lfanew + 3) .. $offset_e_lfanew] | % {$_.ToString('X2')}) -join ''))

    # Read up to where the NT headers are, and then the size of IMAGE_NT_HEADERS64 which should be more than we need
    $totalToRead = $offsetImageNtHeaders + $sizeofImageNtHeaders64
    $bytesImageNtHeaders = Get-Content -Encoding Byte -TotalCount $totalToRead $filename -ErrorAction SilentlyContinue
    if ($bytesImageNtHeaders.Length -lt $totalToRead)
    {
        Write-Verbose "$filename : Not a PE file; less than $totalToRead bytes."
        #Write-Output ""
        return;
    }

    # Verify that the PE signature is present there. (Actually is "PE\0\0" but just going to look for the first two bytes.)
    $peSig = "" + [char]($bytesImageNtHeaders[$offsetImageNtHeaders]) + [char]($bytesImageNtHeaders[$offsetImageNtHeaders+1])
    if ($peSig -ne "PE")
    {
        Write-Verbose "$filename : Not a PE file; 'PE' signature bytes not found."
        #Write-Output ""
        return;
    }

    # Get the offset of the "Characteristics" attribute in the file header
    $offsChar = $offsetImageNtHeaders + $offset_FileHeader + $offset_FileHeader_Characteristics
    # Read the two-byte Characteristics
    $characteristics = [UInt16]('0x{0}' -f (( $bytesImageNtHeaders[($offsChar+1)..$offsChar] | % {$_.ToString('X2')}) -join ''))

    # Get the offset of the two-byte "Subsystem" attribute in the optional headers, and read that attribute
    $offsSubsystem = $offsetImageNtHeaders + $offset_OptionalHeader + $offset_OptionalHeader_Subsystem
    $subsystem = [UInt16]('0x{0}' -f (( $bytesImageNtHeaders[($offsSubsystem+1)..$offsSubsystem] | % {$_.ToString('X2')}) -join ''))

    # Verify that Subsystem is IMAGE_SUBSYSTEM_WINDOWS_GUI or IMAGE_SUBSYSTEM_WINDOWS_CUI
    if ($subsystem -ne $IMAGE_SUBSYSTEM_WINDOWS_GUI -and $subsystem -ne $IMAGE_SUBSYSTEM_WINDOWS_CUI)
    {
        Write-Verbose "$filename : Not a Win32 EXE or DLL; Subsystem = $subsystem."
        #Write-Output ""
        return;
    }

    if ($characteristics -band 0x2000)
    {
        Write-Verbose "$filename : Win32 DLL; Subsystem = $subsystem."
        Write-Output "DLL"
    }
    else
    {
        Write-Verbose "$filename : Win32 EXE; Subsystem = $subsystem."
        Write-Output "EXE"
    }

    #if ($characteristics -band 0x0001) {"IMAGE_FILE_RELOCS_STRIPPED"}
    #if ($characteristics -band 0x0002) {"IMAGE_FILE_EXECUTABLE_IMAGE"}
    #if ($characteristics -band 0x0004) {"IMAGE_FILE_LINE_NUMS_STRIPPED"}
    #if ($characteristics -band 0x0008) {"IMAGE_FILE_LOCAL_SYMS_STRIPPED"}
    #if ($characteristics -band 0x0010) {"IMAGE_FILE_AGGRESIVE_WS_TRIM"}
    #if ($characteristics -band 0x0020) {"IMAGE_FILE_LARGE_ADDRESS_AWARE"}
    #if ($characteristics -band 0x0080) {"IMAGE_FILE_BYTES_REVERSED_LO"}
    #if ($characteristics -band 0x0100) {"IMAGE_FILE_32BIT_MACHINE"}
    #if ($characteristics -band 0x0200) {"IMAGE_FILE_DEBUG_STRIPPED"}
    #if ($characteristics -band 0x0400) {"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"}
    #if ($characteristics -band 0x0800) {"IMAGE_FILE_NET_RUN_FROM_SWAP"}
    #if ($characteristics -band 0x1000) {"IMAGE_FILE_SYSTEM"}
    #if ($characteristics -band 0x2000) {"IMAGE_FILE_DLL"}
    #if ($characteristics -band 0x4000) {"IMAGE_FILE_UP_SYSTEM_ONLY"}
    #if ($characteristics -band 0x8000) {"IMAGE_FILE_BYTES_REVERSED_HI"}
}


####################################################################################################
# Global variables - known file extensions
####################################################################################################
#
# With the -Directory switch, the Get-AppLockerFileInformation cmdlet inspects files with the extensions shown below (GetAlfiDefaultExts). 
# Create-Policies.ps1 (via BuildRulesForFilesInWritableDirectories.ps1) and Scan-Directories.ps1 inspect the content of other files to 
# determine whether any of them are Portable Executable files with non-standard extensions. To save the cost of reading in lots of files that
# are never PE files (never should be, anyway), those scripts consume this script's output and doesn't inspect files with these extensions.
# 
# NOTE THAT IF YOU EDIT THE NeverExecutableExts ARRAY:
# * Make sure the script returns one array of strings: comma after each one except the last.
# * Each extension must begin with a ".".
# * Extensions cannot contain embedded dot characters. For example, a file named "lpc.win32.bundle" has the extension ".bundle" and not ".win32.bundle"
# * Do NOT add any of the extensions that Get-AppLockerFileInformation searches.
# * Order doesn't matter.
# * Do not edit the GetAlfiDefaultExts array.
# 

Set-Variable -Name GetAlfiDefaultExts -Option Constant -Value ".com", ".exe", ".dll", ".ocx", ".msi", ".msp", ".mst", ".bat", ".cmd", ".js", ".ps1", ".vbs", ".appx"
Set-Variable -Name NeverExecutableExts -Option Constant -Value `
    ".admx", ".adml", ".opax", ".opal", 
    ".etl", ".evtx", ".msc", ".pdb",
    ".chm", ".hlp",
    ".gif", ".jpg", ".jpeg", ".png", ".bmp", ".svg", ".ico", ".pfm", ".ttf", ".fon", ".otf", ".cur",
    ".html", ".htm", ".hta", ".css", ".json",
    ".txt", ".log", ".xml", ".xsl", ".ini", ".csv", ".reg", ".mof",
    ".pdf", ".tif", ".tiff", ".xps", ".rtf",
    ".lnk", ".url", ".inf",
    ".odl", ".odlgz", ".odlsent",                                 # OneDrive data files
    ".mui",                                                       # .mui is a DLL but it is always loaded as data-only, so no need for AppLocker rules
    ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",           # Microsoft Word
    ".xls", ".xlsx", ".xlsm", ".xlt", ".xltx", ".xltm",           # Microsoft Excel
    ".ppt", ".pptx", ".pptm", ".pot", ".potx", ".potm", ".pps", ".ppsx", # Microsoft PowerPoint
    ".zip", ".7z", ".tar",
    ".wav", ".wmv", ".mp3", ".mp4", ".mpg", ".mpeg", ".avi", ".mov"

