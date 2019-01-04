function AddNewWorksheet
{
	[CmdletBinding()]
	param (
		[string]
		$tabname
	)
	if ($null -eq $script:ExcelAppInstance) { return $null }
	
	if ($script:ExcelAppInstance.Workbooks.Count -eq 0)
	{
		$workbook = $script:ExcelAppInstance.Workbooks.Add(5)
		$worksheet = $workbook.Sheets(1)
	}
	else
	{
		$workbook = $script:ExcelAppInstance.Workbooks[1]
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