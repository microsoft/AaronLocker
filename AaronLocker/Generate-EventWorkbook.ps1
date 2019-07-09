<#
.SYNOPSIS
Produces a multi-tab Excel workbook containing summary and details of AppLocker events to support advanced analysis.

.DESCRIPTION
Converts output from the Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1 scripts to a multi-tab Excel workbook supporting numerous views of the data, many including graphs.
Worksheets include:
* Summary tab showing date/time ranges of the reported events and other summary information.
* Numbers of distinct users running files from each high-level location such as user profile, hot/removable, non-default root directories, etc.
* Numbers of distinct users running files from each observed publisher.
* Numbers of distinct users running each observed file (by GenericPath).
* All combinations of publishers/products for signed files in events.
* All combinations of publishers/products and generic file paths ("generic" meaning that user-specific paths are replaced with %LOCALAPPDATA%, %USERPROFILE%, etc., as appropriate).
* Paths of unsigned files, with filename alone, file type, and file hash.
* Files and publishers grouped by user.
* Full details from Get-AppLockerEvents.ps1.
With the -RawEventCounts switch, the workbook adds sheets showing raw event counts for each machine, publisher, and user.
These separate tabs enable quick determination of the files running afoul of AppLocker rules and help quickly determine whether/how to adjust the rules.

.PARAMETER AppLockerEventsCsvFile
Optional path to CSV file produced by Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1.
If not specified, this script invokes Get-AppLockerEvents.ps1 on the local computer and processes its output.

.PARAMETER SaveWorkbook
If AppLockerEventsCsvFile is specified and this option is set, the script saves the workbook to the same directory
as the input file and with the same file name but with the default Excel file extension.

.PARAMETER RawEventCounts
If the -RawEventCounts switch is specified, workbook includes additional worksheets focused on raw event counts per machine, per user, and per publisher.
#>

[CmdletBinding(DefaultParameterSetName="GenerateTempCsv")]
param(
    # Path to CSV file produced by Get-AppLockerEvents.ps1
    [parameter(ParameterSetName="NamedCsvFile", Mandatory=$true)]
    [String]
    $AppLockerEventsCsvFile, 

    [parameter(ParameterSetName="NamedCsvFile")]
    [switch]
    $SaveWorkbook,

    [switch]
    $RawEventCounts
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


Write-Host "Reading data from $AppLockerEventsCsvFile" -ForegroundColor Cyan
$csvFull = @(Get-Content $AppLockerEventsCsvFile)
$dataUnfiltered = @($csvFull | ConvertFrom-Csv -Delimiter "`t")
$dataFiltered   = @($dataUnfiltered | Where-Object { $_.EventType -ne $sFiltered })
$eventsSigned   = @($dataFiltered | Where-Object { $_.PublisherName -ne $sUnsigned -and $_.PublisherName -ne $sNoPublisher })
$eventsUnsigned = @($dataFiltered | Where-Object { $_.PublisherName -eq $sUnsigned -or  $_.PublisherName -eq $sNoPublisher })

if ($dataUnfiltered.Length -eq 0)
{
    Write-Warning "No data. Exiting."
    return
}

$nEvents = $dataFiltered.Length
$nSignedEvents = $eventsSigned.Length
$nUnsignedEvents = $eventsUnsigned.Length

if (CreateExcelApplication)
{
    # Array to set sort order descending on Count and then ascending on Name
    $CountDescNameAsc = @( @{ Expression = "Count"; Descending = $true }, @{ Expression = "Name"; Descending = $false} )

    # Lines of text for the summary page
    $tabname = "Summary"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    [System.Collections.ArrayList]$text = @()
    $text.Add( "Summary information" ) | Out-Null
    $text.Add( "" ) | Out-Null
    $text.Add( "Data source:`t" + $dataSourceName ) | Out-Null
    if ($nEvents -gt 0)
    {
        $dtsort = ($dataFiltered.EventTime | Sort-Object); 
        $dtFirst = ([datetime]($dtsort[0])).ToString()
        $dtLast =  ([datetime]($dtsort[$dtsort.Length - 1])).ToString()
    }
    else
    {
        $dtFirst = $dtLast = "N/A"
    }
    $text.Add( "First event:`t" + $dtFirst ) | Out-Null
    $text.Add( "Last event:`t" + $dtLast ) | Out-Null
    $text.Add( "" ) | Out-Null
    $text.Add( "Number of events:`t" + $nEvents.ToString() ) | Out-Null
    $text.Add( "Number of signed-file events:`t" + $nSignedEvents.ToString() ) | Out-Null
    $text.Add( "Number of unsigned-file events:`t" + $nUnsignedEvents.ToString() ) | Out-Null
    # Make sure the result of the pipe is an array, even if only one item.
    $text.Add( "Number of machines reporting events:`t" + ( @($dataUnfiltered.MachineName | Group-Object)).Count.ToString() ) | Out-Null
    $text.Add( "Number of users reporting events:`t" + ( @($dataFiltered.UserName | Group-Object)).Count.ToString() ) | Out-Null
    AddWorksheetFromText -text $text -tabname $tabname

    if ($nEvents -gt 0)
    {
        # Users per location:
        $tabname = "# Users per Location"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object Location, UserName -Unique | Group-Object Location | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        # Change the headers
        $csv[0] = "Location" + "`t" + "# of distinct users"
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
    }

    if ($nEvents -gt 0)
    {
        # Users per publisher:
        $tabname = "# Users per Publisher"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object PublisherName, UserName -Unique | Group-Object PublisherName | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        # Change the headers
        $csv[0] = "PublisherName" + "`t" + "# of distinct users"
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
    }

    if ($nSignedEvents -gt 0)
    {
        # Publisher/product combinations:
        $tabname = "Publisher-product combinations"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($eventsSigned | Select-Object PublisherName, ProductName | Sort-Object PublisherName, ProductName -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nEvents -gt 0)
    {
        # Users per file:
        $tabname = "# Users per File"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object Location, GenericPath, UserName -Unique | Group-Object Location, GenericPath | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        # Change the headers
        $csv[0] = "Location, GenericPath" + "`t" + "# of distinct users"
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
    }

    if ($nSignedEvents -gt 0)
    {
        # Publisher/product/file combinations:
        $tabname = "Signed file info"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($eventsSigned | Select-Object PublisherName, ProductName, Location, GenericPath, FileName, FileType | Sort-Object PublisherName, ProductName, Location, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nUnsignedEvents -gt 0)
    {
        # Analysis of unsigned files:
        $tabname = "Unsigned file info"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($eventsUnsigned | Select-Object Location, GenericPath, FileName, FileType, Hash | Sort-Object Location, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nEvents -gt 0)
    {
        # Files by user
        $tabname = "Files by User"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object UserName, Location, GenericPath, FileType, PublisherName, ProductName | Sort-Object UserName, Location, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nEvents -gt 0)
    {
        # Files by user (details)
        $tabname = "Files by User (details)"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object UserName, MachineName, EventTimeXL, FileType, GenericPath, PublisherName, ProductName | Sort-Object UserName, MachineName, EventTimeXL, FileType, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    # All event data
    AddWorksheetFromCsvFile -filename $AppLockerEventsCsvFileFullPath -tabname "Full details"

    if ($RawEventCounts)
    {
        # Events per machine:
        $tabname = "# Events per Machine"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered.MachineName | Group-Object | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        if ($csv.Length -eq 0) { $csv = @("header") } # No events - insert dummy header row, replaced in a moment
        $csv += @($dataUnfiltered | Where-Object { $_.EventType -eq $sFiltered } | ForEach-Object { $_.MachineName + "`t0" })
        # Change the headers
        if ($csv.Length -gt 0 ) { $csv[0] = "MachineName" + "`t" + "Event count" }
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart

        if ($nEvents -gt 0)
        {
            # Counts of each publisher:
            $tabname = "# Events per Publisher"
            Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
            $csv = @($dataFiltered.PublisherName | Group-Object | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
            # Change the headers
            if ($csv.Length -gt 0 ) { $csv[0] = "PublisherName" + "`t" + "Events" }
            AddWorksheetFromCsvData -csv $csv -tabname $tabname -AddChart
        }

        if ($nEvents -gt 0)
        {
            # Events per user:
            $tabname = "# Events per User"
            Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
            $csv = @($dataFiltered.UserName | Group-Object | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
            # Change the headers
            $csv[0] = "UserName" + "`t" + "Events"
            AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
        }
    }

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


