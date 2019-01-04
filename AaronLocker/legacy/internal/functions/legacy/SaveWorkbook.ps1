function SaveWorkbook
{
	[CmdletBinding()]
	param (
		[string]
		$filename
	)
	
	Write-Host "Saving workbook as `"$filename`"..." -ForegroundColor Cyan
	if ($null -eq $script:ExcelAppInstance) { return }
	if ($script:ExcelAppInstance.Workbooks.Count -eq 0) { return }
	$script:ExcelAppInstance.Workbooks[1].SaveAs($filename)
}