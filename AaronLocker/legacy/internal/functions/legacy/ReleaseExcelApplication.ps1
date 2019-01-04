function ReleaseExcelApplication
{
	[CmdletBinding()]
	param (
		
	)
	
	Write-Host "Releasing Excel..." -ForegroundColor Cyan
	$dummy = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($script:ExcelAppInstance)
	$script:ExcelAppInstance = $null
}