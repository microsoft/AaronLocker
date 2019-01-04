param (
	$TestGeneral = $true,
	
	$TestFunctions = $true,
	
	[ValidateSet('None', 'Default', 'Passed', 'Failed', 'Pending', 'Skipped', 'Inconclusive', 'Describe', 'Context', 'Summary', 'Header', 'Fails', 'All')]
	$Show = "None",
	
	$Include = "*",
	
	$Exclude = ""
)

Write-PSFMessage -Level Important -Message "Starting Tests"

Write-PSFMessage -Level Important -Message "Importing Module"

Remove-Module AaronLocker -ErrorAction Ignore
Import-Module "$PSScriptRoot\..\AaronLocker.psd1"
Import-Module "$PSScriptRoot\..\AaronLocker.psm1" -Force

Write-PSFMessage -Level Important -Message "Creating test result folder"
$null = New-Item -Path "$PSScriptRoot\..\.." -Name TestResults -ItemType Directory -Force

$totalFailed = 0
$totalRun = 0

$testresults = @()

#region Run General Tests
Write-PSFMessage -Level Important -Message "Modules imported, proceeding with general tests"
foreach ($file in (Get-ChildItem "$PSScriptRoot\general" -Filter "*.Tests.ps1"))
{
	Write-PSFMessage -Level Significant -Message "  Executing <c='em'>$($file.Name)</c>"
	$TestOuputFile = Join-Path "$PSScriptRoot\..\..\TestResults" "TEST-$($file.BaseName).xml"
    $results = Invoke-Pester -Script $file.FullName -Show $Show -PassThru -OutputFile $TestOuputFile -OutputFormat NUnitXml
	foreach ($result in $results)
	{
		$totalRun += $result.TotalCount
		$totalFailed += $result.FailedCount
		$result.TestResult | Where-Object { -not $_.Passed } | ForEach-Object {
			$name = $_.Name
			$testresults += [pscustomobject]@{
				Describe  = $_.Describe
				Context   = $_.Context
				Name	  = "It $name"
				Result    = $_.Result
				Message   = $_.FailureMessage
			}
		}
	}
}
#endregion Run General Tests

#region Test Commands
Write-PSFMessage -Level Important -Message "Proceeding with individual tests"
foreach ($file in (Get-ChildItem "$PSScriptRoot\functions" -Recurse -File -Filter "*Tests.ps1"))
{
	if ($file.Name -notlike $Include) { continue }
	if ($file.Name -like $Exclude) { continue }
	
	Write-PSFMessage -Level Significant -Message "  Executing $($file.Name)"
	$TestOuputFile = Join-Path "$PSScriptRoot\..\..\TestResults" "TEST-$($file.BaseName).xml"
    $results = Invoke-Pester -Script $file.FullName -Show $Show -PassThru -OutputFile $TestOuputFile -OutputFormat NUnitXml
	foreach ($result in $results)
	{
		$totalRun += $result.TotalCount
		$totalFailed += $result.FailedCount
		$result.TestResult | Where-Object { -not $_.Passed } | ForEach-Object {
			$name = $_.Name
			$testresults += [pscustomobject]@{
				Describe   = $_.Describe
				Context    = $_.Context
				Name	   = "It $name"
				Result	   = $_.Result
				Message    = $_.FailureMessage
			}
		}
	}
}
#endregion Test Commands

$testresults | Sort-Object Describe, Context, Name, Result, Message | Format-List

if ($totalFailed -eq 0) { Write-PSFMessage -Level Critical -Message "All <c='em'>$totalRun</c> tests executed without a single failure!" }
else { Write-PSFMessage -Level Critical -Message "<c='em'>$totalFailed tests</c> out of <c='sub'>$totalRun</c> tests failed!" }

if ($totalFailed -gt 0)
{
	throw "$totalFailed / $totalRun tests failed!"
}