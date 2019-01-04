function AddWorksheetFromText
{
	[CmdletBinding()]
	param (
		[string[]]
		$text,
		
		[string]
		$tabname
	)
	
	Write-Host "Populating tab `"$tabname`"..." -ForegroundColor Cyan
	
	if ($null -eq $script:ExcelAppInstance) { return $null }
	
	$worksheet = AddNewWorksheet($tabname)
	$worksheet.UsedRange.VerticalAlignment = -4160 # xlTop
	
	$row = [int]1
	foreach ($line in $text)
	{
		$iCol = [int][char]'A'
		$lineparts = $line.Split("`t")
		foreach ($part in $lineparts)
		{
			$cell = ([char]$iCol).ToString() + $row.ToString()
			$worksheet.Range($cell).FormulaR1C1 = $part
			$iCol++
		}
		$row++
	}
	
	$null = $worksheet.Cells.EntireColumn.AutoFit()
	
	# Release COM interface references
	$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet)
}