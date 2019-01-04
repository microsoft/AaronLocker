<#
This script publishes the module to the gallery.
It expects as input an ApiKey authorized to publish the module.

Insert any build steps you may need to take before publishing it here.
#>
param (
	$ApiKey
)

# Prepare publish folder
Write-PSFMessage -Level Important -Message "Creating and populating publishing directory"
$publishDir = New-Item -Path $env:SYSTEM_DEFAULTWORKINGDIRECTORY -Name publish -ItemType Directory
Copy-Item -Path "$($env:SYSTEM_DEFAULTWORKINGDIRECTORY)\AaronLocker" -Destination $publishDir.FullName -Recurse -Force

# Create commands.ps1
$text = @()
Get-ChildItem -Path "$($publishDir.FullName)\AaronLocker\internal\functions\" -Recurse -File -Filter "*.ps1" | ForEach-Object {
	$text += [System.IO.File]::ReadAllText($_.FullName)
}
Get-ChildItem -Path "$($publishDir.FullName)\AaronLocker\functions\" -Recurse -File -Filter "*.ps1" | ForEach-Object {
	$text += [System.IO.File]::ReadAllText($_.FullName)
}
$text -join "`n`n" | Set-Content -Path "$($publishDir.FullName)\AaronLocker\commands.ps1"

# Create resourcesBefore.ps1
$processed = @()
$text = @()
foreach ($line in (Get-Content "$($PSScriptRoot)\filesBefore.txt" | Where-Object { $_ -notlike "#*" }))
{
	if ([string]::IsNullOrWhiteSpace($line)) { continue }
	
	$basePath = Join-Path "$($publishDir.FullName)\AaronLocker" $line
	foreach ($entry in (Resolve-PSFPath -Path $basePath))
	{
		$item = Get-Item $entry
		if ($item.PSIsContainer) { continue }
		if ($item.FullName -in $processed) { continue }
		$text += [System.IO.File]::ReadAllText($item.FullName)
		$processed += $item.FullName
	}
}
if ($text) { $text -join "`n`n" | Set-Content -Path "$($publishDir.FullName)\AaronLocker\resourcesBefore.ps1" }

# Create resourcesAfter.ps1
$processed = @()
$text = @()
foreach ($line in (Get-Content "$($PSScriptRoot)\filesAfter.txt" | Where-Object { $_ -notlike "#*" }))
{
	if ([string]::IsNullOrWhiteSpace($line)) { continue }
	
	$basePath = Join-Path "$($publishDir.FullName)\AaronLocker" $line
	foreach ($entry in (Resolve-PSFPath -Path $basePath))
	{
		$item = Get-Item $entry
		if ($item.PSIsContainer) { continue }
		if ($item.FullName -in $processed) { continue }
		$text += [System.IO.File]::ReadAllText($item.FullName)
		$processed += $item.FullName
	}
}
if ($text) { $text -join "`n`n" | Set-Content -Path "$($publishDir.FullName)\AaronLocker\resourcesAfter.ps1" }

# Publish to Gallery
Publish-Module -Path "$($publishDir.FullName)\AaronLocker" -NuGetApiKey $ApiKey -Force