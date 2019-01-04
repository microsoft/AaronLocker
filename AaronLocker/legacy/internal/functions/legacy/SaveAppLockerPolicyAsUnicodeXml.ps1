function SaveAppLockerPolicyAsUnicodeXml
{
	[CmdletBinding()]
	param (
		[Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]
		$ALPolicy,
		
		[string]
		$xmlFilename
	)
	
	SaveXmlDocAsUnicode -xmlDoc ([xml]($ALPolicy.ToXml())) -xmlFilename $xmlFilename
}