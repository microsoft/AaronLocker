function SaveXmlDocAsUnicode
{
<#
	.SYNOPSIS
		Writes an xml document to file with unicode encoding
	
	.DESCRIPTION
		Writes an xml document to file with unicode encoding
	
	.PARAMETER xmlDoc
		The document to write.
	
	.PARAMETER xmlFilename
		The path to write it to.
	
	.EXAMPLE
		PS C:\> SaveXmlDocAsUnicode -xmlDoc $doc -xmlFilename "C:\temp\example.xml"
	
		Exports the specified document to C:\temp\example.xml
#>
	[CmdletBinding()]
	param (
		[System.Xml.XmlDocument]
		$xmlDoc,
		
		[string]
		$xmlFilename
	)
	$xws = [System.Xml.XmlWriterSettings]::new()
	$xws.Encoding = [System.Text.Encoding]::Unicode
	$xws.Indent = $true
	$xw = [System.Xml.XmlWriter]::Create($xmlFilename, $xws)
	$xmlDoc.Save($xw)
	$xw.Close()
}