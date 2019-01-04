function AddWorksheetFromCsvData
{
	[CmdletBinding()]
	param (
		[string[]]
		$csv,
		
		[string]
		$tabname,
		
		[string]
		$CrLfEncoded
		
	)
	Write-Host "Preparing data for tab `"$tabname`"..." -ForegroundColor Cyan
	
	if ($null -eq $script:ExcelAppInstance) { return $null }
	
	if ($null -ne $csv)
	{
		$OutputEncodingPrevious = $OutputEncoding
		$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode
		
		$tempfile = [System.IO.Path]::GetTempFileName()
		
		$csv | Out-File $tempfile -Encoding unicode
		
		AddWorksheetFromCsvFile -filename $tempfile -tabname $tabname -CrLfEncoded $CrLfEncoded
		
		Remove-Item $tempfile
		
		$OutputEncoding = $OutputEncodingPrevious
	}
	else
	{
		$worksheet = AddNewWorksheet -tabname $tabname
		$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet)
	}
}