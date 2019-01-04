function CreateExcelFromCsvFile
{
	[CmdletBinding()]
	param (
		[string]
		$filename,
		
		[string]
		$tabname,
		
		[string]
		$CrLfEncoded,
		
		[string]
		$saveAsName
	)
	
	if (CreateExcelApplication)
	{
		AddWorksheetFromCsvFile -filename $filename -tabname $tabname -CrLfEncoded $CrLfEncoded
		if ($saveAsName.Length -gt 0)
		{
			SaveWorkbook -filename $saveAsName
		}
		ReleaseExcelApplication
	}
}