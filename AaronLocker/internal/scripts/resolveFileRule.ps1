<#
This policy is used by the SourcePathRule rule object's 'Resolve()' method call to resolve the source file to the intended rules.
Commands converting rule objects into rules should call that method on SourcePathRule objects, use that methods return values and discard the original object.
#>
[AaronLocker.SourcePathRule]::ResolutionScript = {
	param (
		[AaronLocker.SourcePathRule]
		$Rule
	)
	$paramConvertToALPolicy = @{
		Path				  = $Rule.Path
		Recurse			      = $Rule.Recurse
		EnforceMinimumVersion = $Rule.EnforceMinimumVersion
		RuleNamePrefix	      = $Rule.Label
	}
	
	foreach ($ruleItem in (ConvertTo-ALPolicy @paramConvertToALPolicy))
	{
		$ruleItem.Collection = $Rule.Collection
		$ruleItem.Action = $Rule.Action
		$ruleItem
	}
}