<#
.SYNOPSIS
Produces a multi-tab Excel workbook containing summary and details of AppLocker events to support advanced analysis.

.DESCRIPTION
Converts the saved output from the Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1 scripts to a multi-tab Excel workbook supporting numerous views of the data, including:
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
Path to CSV file produced by Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1, ideally without any attributes removed, but must contain at least these: MachineName, PublisherName, ProductName, GenericPath, GenericDir, FileName, FileType, Hash

.PARAMETER SaveWorkbook
If set, saves workbook to same directory as input file with same file name and default Excel file extension.
#>


param(
    # Path to CSV file produced by Get-AppLockerEvents.ps1
    [parameter(Mandatory=$true)]
    [String]
    $AppLockerEventsCsvFile, 

    [switch]
    $SaveWorkbook
)

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

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file. Contains Excel-generation scripts.
. $rootDir\Support\Config.ps1

$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

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
    $text = @()
    $dtsort = ($dataFiltered.EventTime | Sort-Object); 
    $text += "Summary information"
    $text += ""
    $text += "Data source:`t" + [System.IO.Path]::GetFileName($AppLockerEventsCsvFile)
    $text += "First event:`t" + ([datetime]($dtsort[0])).ToString()
    $text += "Last event:`t" + ([datetime]($dtsort[$dtsort.Length - 1])).ToString()
    $text += "Number of events:`t" + $dataFiltered.Count.ToString()
    $text += "Number of signed-file events:`t" + $eventsSigned.Count.ToString()
    $text += "Number of unsigned-file events:`t" + $eventsUnsigned.Count.ToString()
    # Make sure the result of the pipe is an array, even if only one item.
    $text += "Number of machines reporting events:`t" + ( @() + ($dataUnfiltered.MachineName | Group-Object)).Count.ToString()
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

$OutputEncoding = $OutputEncodingPrevious


