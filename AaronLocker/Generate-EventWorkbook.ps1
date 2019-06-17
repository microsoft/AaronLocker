<#
.SYNOPSIS
Produces a multi-tab Excel workbook containing summary and details of AppLocker events to support advanced analysis.

.DESCRIPTION
Converts output from the Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1 scripts to a multi-tab Excel workbook supporting numerous views of the data, including:
* Summary tab showing date/time ranges of the reported events and other summary information.
* List of machines reporting events, and the number of events per machine.
* List of publishers of signed files appearing in events, and the number of events per publisher.
* All combinations of publishers/products for signed files in events.
* All combinations of publishers/products and generic file paths ("generic" meaning that user-specific paths are replaced with %LOCALAPPDATA%, %USERPROFILE%, etc., as appropriate).
* Paths of unsigned files, with filename alone, file type, and file hash.
* Files grouped by user.
* Full details from Get-AppLockerEvents.ps1.
These separate tabs enable quick determination of the files running afoul of AppLocker rules and help quickly determine whether/how to adjust the rules.

.PARAMETER AppLockerEventsCsvFile
Optional path to CSV file produced by Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1.
If not specified, this script invokes Get-AppLockerEvents.ps1 on the local computer and processes its output.

.PARAMETER SaveWorkbook
If AppLockerEventsCsvFile is specified and this option is set, the script saves the workbook to the same directory
as the input file and with the same file name but with the default Excel file extension.
#>

[CmdletBinding(DefaultParameterSetName="GenerateTempCsv")]
param(
    # Path to CSV file produced by Get-AppLockerEvents.ps1
    [parameter(ParameterSetName="NamedCsvFile", Mandatory=$true)]
    [String]
    $AppLockerEventsCsvFile, 

    [parameter(ParameterSetName="NamedCsvFile")]
    [switch]
    $SaveWorkbook
)

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file. Contains Excel-generation scripts.
. $rootDir\Support\Config.ps1

$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

$tempfile = [string]::Empty

if ($AppLockerEventsCsvFile)
{
    if (!(Test-Path($AppLockerEventsCsvFile)))
    {
        Write-Warning "File not found: $AppLockerEventsCsvFile"
        return
    }

    # Get absolute path to input file. (Note that [System.IO.Path]::GetFullName doesn't do this...)
    $AppLockerEventsCsvFileFullPath = $AppLockerEventsCsvFile
    if (!([System.IO.Path]::IsPathRooted($AppLockerEventsCsvFile)))
    {
        $AppLockerEventsCsvFileFullPath = [System.IO.Path]::Combine((Get-Location).Path, $AppLockerEventsCsvFile)
    }
    $dataSourceName = [System.IO.Path]::GetFileName($AppLockerEventsCsvFile)
}
else
{
    $tempfile = [System.IO.Path]::GetTempFileName()
    $AppLockerEventsCsvFileFullPath = $AppLockerEventsCsvFile = $tempfile
    $dataSourceName = "(Get-AppLockerEvents.ps1 output)"
    & $rootDir\Get-AppLockerEvents.ps1 | Out-File $tempfile -Encoding unicode
}


# String constant
$sFiltered = "FILTERED"

if (CreateExcelApplication)
{
    Write-Host "Reading data from $AppLockerEventsCsvFile" -ForegroundColor Cyan
    $csvFull = @(Get-Content $AppLockerEventsCsvFile)
    #Write-Host "Converting to CSV" -ForegroundColor Yellow
    $dataUnfiltered = @($csvFull | ConvertFrom-Csv -Delimiter "`t")
    #Write-Host "Getting filtered events" -ForegroundColor Yellow
    $dataFiltered = @($dataUnfiltered | Where-Object { $_.EventType -ne $sFiltered })
    #Write-Host "Getting signed events" -ForegroundColor Yellow
    $eventsSigned   = @($dataFiltered | Where-Object { $_.PublisherName -ne "-" })
    #Write-Host "Getting unsigned events" -ForegroundColor Yellow
    $eventsUnsigned = @($dataFiltered | Where-Object { $_.PublisherName -eq "-" })

    # Lines of text for the summary page
    $tabname = "Summary"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    [System.Collections.ArrayList]$text = @()
    $dtsort = ($dataFiltered.EventTime | Sort-Object); 
    $text.Add( "Summary information" ) | Out-Null
    $text.Add( "" ) | Out-Null
    $text.Add( "Data source:`t" + $dataSourceName ) | Out-Null
    $text.Add( "First event:`t" + ([datetime]($dtsort[0])).ToString() ) | Out-Null
    $text.Add( "Last event:`t" + ([datetime]($dtsort[$dtsort.Length - 1])).ToString() ) | Out-Null
    $text.Add( "Number of events:`t" + $dataFiltered.Count.ToString() ) | Out-Null
    $text.Add( "Number of signed-file events:`t" + $eventsSigned.Count.ToString() ) | Out-Null
    $text.Add( "Number of unsigned-file events:`t" + $eventsUnsigned.Count.ToString() ) | Out-Null
    # Make sure the result of the pipe is an array, even if only one item.
    # Could also do this as ($dataUnfiltered | Select-Object MachineName -Unique).Count
    $text.Add( "Number of machines reporting events:`t" + ( @($dataUnfiltered.MachineName | Group-Object)).Count.ToString() ) | Out-Null
    AddWorksheetFromText -text $text -tabname $tabname

    # Events per machine:
    $tabname = "Machines and event counts"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($dataFiltered.MachineName | Group-Object | Select-Object Name, Count | Sort-Object Name | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    $csv += ($dataUnfiltered | Where-Object { $_.EventType -eq $sFiltered } | ForEach-Object { $_.MachineName + "`t0" })
    AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded ""

    # Counts of each publisher:
    $tabname = "Publishers and event counts"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($dataFiltered.PublisherName | Group-Object | Select-Object Name, Count | Sort-Object Name | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname

    # Publisher/product combinations:
    $tabname = "Publisher-product combinations"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($eventsSigned | Select-Object PublisherName, ProductName | Sort-Object PublisherName, ProductName -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname

    # Publisher/product/file combinations:
    $tabname = "Signed file info"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($eventsSigned | Select-Object PublisherName, ProductName, GenericPath, FileName, FileType | Sort-Object PublisherName, ProductName, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname

    #   # Publisher/product/directory combinations:
    #   $tabname = "Signed file info (dir only)"
    #   Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    #   $csv = ($eventsSigned | Select-Object PublisherName, ProductName, GenericDir, FileType | Sort-Object PublisherName, ProductName, GenericDir -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    #   AddWorksheetFromCsvData -csv $csv -tabname $tabname

    # Analysis of unsigned files:
    $tabname = "Unsigned file info"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($eventsUnsigned | Select-Object GenericPath, FileName, FileType, Hash | Sort-Object GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname

    #   # Analysis of unsigned files (dir only):
    #   $tabname = "Dirs of unsigned files"
    #   Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    #   $csv = ($eventsUnsigned | Select-Object GenericDir | Sort-Object GenericDir -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    #   AddWorksheetFromCsvData -csv $csv -tabname $tabname

    # Events per user:
    $tabname = "Users and event counts"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($dataFiltered.UserName | Group-Object | Select-Object Name, Count | Sort-Object Name | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded ""

    # Per-user details
    $tabname = "Files by user"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($dataFiltered | Select-Object UserName, GenericPath, PublisherName, ProductName | Sort-Object UserName, GenericPath, PublisherName, ProductName -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname

    # Per-user details
    $tabname = "Files by user (details)"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    $csv = ($dataFiltered | Select-Object UserName, MachineName, EventTimeXL, GenericPath, PublisherName, ProductName | Sort-Object UserName, MachineName, EventTimeXL, GenericPath, PublisherName, ProductName -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
    AddWorksheetFromCsvData -csv $csv -tabname $tabname

    # All event data
    AddWorksheetFromCsvFile -filename $AppLockerEventsCsvFileFullPath -tabname "Full details"

    SelectFirstWorksheet

    if ($SaveWorkbook)
    {
        $xlFname = [System.IO.Path]::ChangeExtension($AppLockerEventsCsvFileFullPath, ".xlsx")
        SaveWorkbook -filename $xlFname
    }

    ReleaseExcelApplication
}

if ($tempfile.Length -gt 0)
{
    Remove-Item $tempfile
}

$OutputEncoding = $OutputEncodingPrevious


