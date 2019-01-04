function CreateExcelApplication
{
	[CmdletBinding()]
	param (
		
	)
	Write-Host "Starting Excel..." -ForegroundColor Cyan
	$script:ExcelAppInstance = New-Object -ComObject excel.application
	if ($null -ne $script:ExcelAppInstance)
	{
		$script:ExcelAppInstance.Visible = $true
		return $true
	}
	else
	{
		Write-Error "Apparently Excel is not installed. Can't create an Excel document without it. Exiting..."
		return $false
	}
}