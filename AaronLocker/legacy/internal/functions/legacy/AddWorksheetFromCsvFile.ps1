function AddWorksheetFromCsvFile
{
	[CmdletBinding()]
	param (
		[string]
		$filename,
		
		[string]
		$tabname,
		
		[string]
		$CrLfEncoded
	)
	
	Write-Host "Populating tab `"$tabname`"..." -ForegroundColor Cyan
	
	if ($null -eq $script:ExcelAppInstance) { return $null }
	
	$worksheet = AddNewWorksheet -tabname $tabname
	
	### Build the QueryTables.Add command
	### QueryTables does the same as when clicking "Data -> From Text" in Excel
	$TxtConnector = ("TEXT;" + $filename)
	$Connector = $worksheet.QueryTables.add($TxtConnector, $worksheet.Range("A1"))
	$query = $worksheet.QueryTables.item($Connector.name)
	$query.TextFileTabDelimiter = $true
	
	### Execute & delete the import query
	$null = $query.Refresh()
	$query.Delete()
	
	if ($CrLfEncoded.Length -gt 0)
	{
		# Replace linebreak-replacement sequence in CSV with CRLF.
		$null = $worksheet.UsedRange.Replace($CrLfEncoded, "`r`n")
	}
	
	# Formatting: autofilter, font size, vertical alignment, freeze top row
	$null = $worksheet.Cells.AutoFilter()
	$worksheet.Cells.Font.Size = 9.5
	$worksheet.UsedRange.VerticalAlignment = -4160 # xlTop
	$script:ExcelAppInstance.ActiveWindow.SplitColumn = 0
	$script:ExcelAppInstance.ActiveWindow.SplitRow = 1
	$script:ExcelAppInstance.ActiveWindow.FreezePanes = $true
	$script:ExcelAppInstance.ActiveWindow.Zoom = 80
	
	$null = $worksheet.Range("A2").Select()
	
	# Formatting: autosize column widths, then set maximum width (except on last column)
	$maxWidth = 40
	$maxHeight = 120
	
	$null = $worksheet.Cells.EntireColumn.AutoFit()
	$ix = 1
	# Do this until the next to last column; don't set max width on the last column
	while ($worksheet.Cells(1, $ix + 1).Text.Length -gt 0)
	{
		$cells = $worksheet.Cells(1, $ix)
		#Write-Host ($cells.Text + "; " + $cells.ColumnWidth)
		if ($cells.ColumnWidth -gt $maxWidth) { $cells.ColumnWidth = $maxWidth }
		$ix++
	}
	
	# Formatting: autosize row heights, then set maximum height (if CrLf replacement on)
	$null = $worksheet.Cells.EntireRow.AutoFit()
	# If line breaks added, limit autofit row height to 
	if ($CrLfEncoded.Length -gt 0)
	{
		$ix = 1
		while ($worksheet.Cells($ix, 1).Text.Length -gt 0)
		{
			$cells = $worksheet.Cells($ix, 1)
			#Write-Host ($ix.ToString() + "; " + $cells.RowHeight)
			if ($cells.RowHeight -gt $maxHeight) { $cells.RowHeight = $maxHeight }
			$ix++
		}
	}
	
	# Release COM interface references
	$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($query)
	$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Connector)
	$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet)
}