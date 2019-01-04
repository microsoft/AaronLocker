$script:_ConfigPath = "$($env:APPDATA)\WindowsPowerShell\AaronLocker\config.json"
$script:_RulesFolder = "$($env:APPDATA)\WindowsPowerShell\AaronLocker"
if (-not (Test-Path $script:_RulesFolder)) { $null = New-Item -Path $script:_RulesFolder -ItemType Directory -Force }
$script:config = Import-Configuration

$script:_PolicyData = @{ }
foreach ($policyFile in (Get-ChildItem "$($script:_RulesFolder)\*.policy.clixml"))
{
	$policy = Import-Clixml -Path $policyFile.FullName
	$script:_PolicyData[$policy.Name] = $policy
}
if (-not $script:_PolicyData[$script:config.ActivePolicy])
{
	$script:_PolicyData[$script:config.ActivePolicy] = New-Object AaronLocker.Policy
	$script:_PolicyData[$script:config.ActivePolicy].Name = $script:config.ActivePolicy
	$script:_PolicyData[$script:config.ActivePolicy] | Export-Clixml -Path "$($script:_RulesFolder)\$($script:config.ActivePolicy).policy.clixml"
}