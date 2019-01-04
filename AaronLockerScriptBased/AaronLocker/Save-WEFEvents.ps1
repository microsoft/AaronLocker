<#
.SYNOPSIS
Captures forwarded events to a CSV file with the timestamp embedded in the file name.
Intended to be executed on a Windows Event Collector server.

.PARAMETER rootdir
Directory in which to create the CSV file.

.PARAMETER daysBack
Number of days ago from which to start retrieving data. E.g., "-daysBack 5" pulls data from the last 5 days.

.PARAMETER label
Name to insert into the filename (can be useful to distinguish sources).

#>

param(
    [parameter(Mandatory=$false)]
    [string]
    $rootdir,

    [parameter(Mandatory=$false)]
    [int]
    $daysBack = 0,

    [parameter(Mandatory=$false)]
    [string]
    $label = ""
)

if (!$rootdir) { $rootdir = "." }

$strTimestamp = [datetime]::Now.ToString("yyyyMMdd-HHmm")
if ($label.Length -eq 0)
{
    $filenameFull = [System.IO.Path]::Combine($rootdir, "ForwardedEvents-" + $strTimestamp + ".csv")
}
else
{
    $filenameFull = [System.IO.Path]::Combine($rootdir, "ForwardedEvents-" + $label + "-" + $strTimestamp + ".csv")
}

$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

if ($daysBack -gt 0)
{
    $csvFull = .\Get-AppLockerEvents.ps1 -ForwardedEvents -NoAutoNGEN -FromDateTime ([datetime]::Now.AddDays(-$daysBack))
}
else
{
    $csvFull = .\Get-AppLockerEvents.ps1 -ForwardedEvents -NoAutoNGEN
}

$csvFull | Out-File -Encoding unicode $filenameFull
Write-Host "Events written to $filenameFull" -ForegroundColor Cyan

