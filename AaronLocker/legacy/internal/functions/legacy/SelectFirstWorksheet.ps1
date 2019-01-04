function SelectFirstWorksheet
{
	[CmdletBinding()]
	param (
		
	)
	if ($null -eq $script:ExcelAppInstance) { return }
	if ($script:ExcelAppInstance.Workbooks.Count -eq 0) { return }
	$dummy = $script:ExcelAppInstance.Workbooks[1].Sheets(1).Select()
}