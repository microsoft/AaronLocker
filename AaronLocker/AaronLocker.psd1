@{
	# Script module or binary module file associated with this manifest
	RootModule = 'AaronLocker.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.0.0'
	
	# ID used to uniquely identify this module
	GUID = 'ee9f8d0f-b919-47ce-aa02-24fa4520e6ed'
	
	# Author of this module
	Author = 'Aaron Margosis'
	
	# Company or vendor of this module
	CompanyName = ''
	
	# Copyright statement for this module
	Copyright = 'Copyright (c) 2018 Aaron Margosis'
	
	# Description of the functionality provided by this module
	Description = 'Manages and applies AppLocker policies'
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.0'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules = @('AppLocker')
	
	# Assemblies that must be loaded prior to importing this module
	RequiredAssemblies = @('bin\AaronLocker.dll')
	
	# Type files (.ps1xml) to be loaded when importing this module
	TypesToProcess = @('xml\AaronLocker.Types.ps1xml')
	
	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess = @('xml\AaronLocker.Format.ps1xml')
	
	# Functions to export from this module
	FunctionsToExport  = @(
		'Get-ALConfiguration'
		'Set-ALConfiguration'
		
		'ConvertTo-ALAppLockerXML'
		'Export-ALAppLockerPolicy'
		
		'Export-ALPolicy'
		'Get-ALPolicy'
		'Import-ALPolicy'
		'New-ALPolicy'
		'Remove-ALPolicy'
		'Set-ALActivePolicy'
		
		'Add-ALRule'
		'Add-ALRuleHash'
		'Add-ALRulePath'
		'Add-ALRulePublisher'
		'Add-ALRuleSourcePath'
		'Get-ALRule'
		'Remove-ALRule'
	)
	
	# Cmdlets to export from this module
	CmdletsToExport = ''
	
	# Variables to export from this module
	VariablesToExport = ''
	
	# Aliases to export from this module
	AliasesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			# Tags = @()
			
			# A URL to the license for this module.
			# LicenseUri = ''
			
			# A URL to the main website for this project.
			# ProjectUri = ''
			
			# A URL to an icon representing this module.
			# IconUri = ''
			
			# ReleaseNotes of this module
			# ReleaseNotes = ''
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}