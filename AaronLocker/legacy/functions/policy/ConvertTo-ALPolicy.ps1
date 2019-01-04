function ConvertTo-ALPolicy
{
<#
	.SYNOPSIS
		Builds tightly-scoped but forward-compatible AppLocker rules for files in user-writable directories.
	
	.DESCRIPTION
		This script takes a list of one or more file system objects (files and/or directories) and generates rules to allow execution of the corresponding files.
		
		Rules generated with this script can be incorporated into comprehensive rule sets using New-ALPolicyScan.
		
		Publisher rules are generated where possible:
		* Publisher rules restrict to a specific binary name, product name, and publisher, and (optionally) the identified version or above.
		* Redundant rules are removed; if multiple versions of a specific file are found, the rule allows execution of the lowest-identified version or above.
		Hash rules are generated when publisher rules cannot be created.
		The script creates rule names and descriptions designed for readability in the Security Policy editor. The RuleNamePrefix option enables you to give each rule in the set a common prefix (e.g., "OneDrive") to make the source of the rule more apparent and so that related rules can be grouped alphabetically by name.
		The rules' EnforcementMode is left NotConfigured. (New-ALPolicyScan takes care of setting EnforcementMode in the larger set.)
		(Note that the New-AppLockerPolicy's -Optimize switch "overoptimizes," allowing any file name within a given publisher and product name. Not using that.)
		
		File system objects can be identified on the command line with -Path, or listed in a file (one object per line) referenced by -FileOfFileSystemObjects.
		
		This script determines whether each object is a file or a directory. For directories, this script enumerates and identifies EXE, DLL, and Script files based on file extension. Subdirectories are scanned if the -Recurse switch is specified on the command line.
		
		The intent of this script is to create fragments of policies that can be incorporated into a "master" policy in a modular way.
		For example, create a file representing the rules needed to allow OneDrive to run, and separate files for LOB apps.
		If/when the OneDrive rules need to be updated, they can be updated in isolation and those results incorporated into a new master set.
	
	.PARAMETER Path
		An array of file paths and/or directory paths to scan. The array can be a comma-separated list of file system paths.
		Either Path or InputFile must be specified.
	
	.PARAMETER InputFile
		The name of a file containing a list of file paths and/or directory paths to scan; one path to a line.
		Either Path or InputFile must be specified.
	
	.PARAMETER Recurse
		If this switch is specified, scanning of directories includes subdirectories; otherwise, only files in the named directory are scanned.
	
	.PARAMETER EnforceMinimumVersion
		If this switch is specified, generated publisher rules enforce minimum file version based on versions of the scanned files; otherwise rules do not enforce file versions
	
	.PARAMETER RuleNamePrefix
		Optional: If specified, all rule names begin with the specified RuleNamePrefix.
	
	.EXAMPLE
		ConvertTo-ALPolicy -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -RuleNamePrefix OneDrive
		
		Scans the OneDrive directory and subdirectories in the current user's profile.
		All generated rule names will begin with "OneDrive".
		The generated rules are written to ..\WorkingFiles\OneDriveRules.xml.
#>
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true, ParameterSetName = "OnCommandLine", ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('FullName')]
		[String[]]
		$Path,
		
		[parameter(Mandatory = $true, ParameterSetName = "SpecifiedInFile")]
		[String]
		$InputFile,
		
		[switch]
		$Recurse,
		
		[switch]
		$EnforceMinimumVersion,
		
		[String]
		$RuleNamePrefix
	)
	
	begin
	{
		#region Utility Function
		function Add-Policy
		{
			[CmdletBinding()]
			param (
				[Parameter(ValueFromPipeline = $true)]
				$FileInformation,
				
				[System.Collections.Hashtable]
				$Policies,
				
				[string]
				$Prefix
			)
			
			process
			{
				foreach ($fileInformationObject in $FileInformation)
				{
					# Favor publisher rule; hash rule otherwise
					$policy = New-AppLockerPolicy -FileInformation $fileInformationObject -RuleType Publisher, Hash
					
					foreach ($ruleCollection in $policy.RuleCollections)
					{
						$rtype = $ruleCollection.RuleCollectionType
						foreach ($rule in $ruleCollection)
						{
							#region Publisher rule - file is signed and has required PE version information
							if ($rule -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule])
							{
								$pubInfo = $rule.PublisherConditions
								# Key on file name, product name, and publisher name; don't incorporate version number into the key
								$key = $pubInfo.BinaryName + "|" + $pubInfo.ProductName + "|" + $pubInfo.PublisherName
								# Build new rule name and description
								$rule.Description = "Product: " + $pubInfo.ProductName + "`r`n" + "Publisher: " + $pubInfo.PublisherName + "`r`n" + "Original path: " + $fileInformationObject.Path.Path
								$rule.Name = $Prefix + $pubInfo.BinaryName
								$pubInfo.BinaryVersionRange.HighSection = $null
								if ($EnforceMinimumVersion)
								{
									# Allow scanned version and above
									$rule.Name += ", v" + $pubInfo.BinaryVersionRange.LowSection.ToString() + " and above"
								}
								else
								{
									$pubInfo.BinaryVersionRange.LowSection = $null
								}
								if (-not $Policies.ContainsKey($key))
								{
									# Add this publisher rule to the collection
									#DBG "PUBLISHER RULE (" + $rtype + "): ADDING " + $key
									$Policies.Add($key, $policy)
								}
								elseif ($EnforceMinimumVersion)
								{
									# File already seen; see whether the newly-scanned file has a lower file version that needs to be allowed
									$rulesPrev = $Policies[$key]
									foreach ($rcPrev in $rulesPrev.RuleCollections)
									{
										foreach ($rulePrev in $rcPrev)
										{
											# Get the previously-scanned file version; compare to the new one
											$verPrev = $rulePrev.PublisherConditions.BinaryVersionRange.LowSection
											$verCurr = $pubInfo.BinaryVersionRange.LowSection
											if ($verCurr.CompareTo($verPrev) -lt 0)
											{
												# The new one is a lower file version; replace the rule we had with the new one.
												#DBG $pubInfo.BinaryName + " REPLACE WITH EARLIER VERSION, FROM " + $verPrev.ToString() + " TO " + $verCurr.ToString()
												$Policies[$key] = $policy
											}
											else
											{
												#DBG $pubInfo.BinaryName + " KEEPING VERSION " + $verCurr.ToString() + " IN FAVOR OF " + $verPrev.ToString()
											}
										}
									}
								}
							}
							#endregion Publisher rule - file is signed and has required PE version information
							
							#region Hash Rule
							elseif ($rule -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashRule])
							{
								# Hash rule - file is missing signature and/or PE version information
								# Record the full path into the policy
								$hashInfo = $rule.HashConditions.Hashes
								# Key on file name and hash
								$key = $hashInfo.SourceFileName + "|" + $hashInfo.HashDataString
								if (-not $Policies.ContainsKey($key))
								{
									$Policies[$key] = New-Object AaronLocker.HashRule -Property @{
										Label = "$($Prefix)$($rule.Name) - HASH RULE"
										Name  = "$($Prefix)$($rule.Name) - HASH RULE"
										Description = "Identified in: $($fileInformationObject.Path.Path)"
									}
									# Default rule name is just the file name; append "HASH RULE"
									# Set the rule description to the full path.
									# If the same file appears in multiple locations, one path will be picked; it doesn't matter which
									$rule.Name = $Prefix + $rule.Name + " - HASH RULE"
									$rule.Description = "Identified in: " + $fileInformationObject.Path.Path
									# Add this hash rule to the collection
									#DBG "HASH RULE (" + $rtype + "): ADDING " + $key
									$Policies.Add($key, $policy)
								}
								else
								{
									# Saw an identical file already
									# "HASH RULE (" + $rtype + "): ALREADY HAVE " + $key
								}
							}
							#endregion Hash Rule
						}
					}
				}
			}
		}
		#endregion Utility Function
		
		#region Handle Inputfile parameter
		if ($InputFile)
		{
			# Test path of the file name, verify that it's a file
			if ((Test-Path $InputFile) -and ((Get-Item $InputFile) -is [System.IO.FileInfo]))
			{
				$Path = Get-Content $InputFile
			}
			else
			{
				throw "Invalid file path: $InputFile"
			}
		}
		#endregion Handle Inputfile parameter
		
		# If RuleNamePrefix specified, append ": " to it before incorporating into rule names
		if ($RuleNamePrefix.Length -gt 0)
		{
			$RuleNamePrefix += ": "
		}
		
		# Hash table of rules with redundant entries removed
		$policies = @{ }
		$countItems = 0
		
		$paramGetAppLockerFileInformation = @{
			FileType = 'Exe', 'Dll', 'Script'
			Recurse  = $Recurse.ToBool()
		}
	}
	process
	{
		#region Process all specified paths and build the policies dictionary
		foreach ($fileSystempath in $Path)
		{
			$countItems = $countItems + 1
			
			# E.g., in case of blank lines in input file
			$fileSystempath = $fileSystempath.Trim()
			if ($fileSystempath.Length -gt 0)
			{
				if (Test-Path $fileSystempath)
				{
					# Determine whether directory or file
					$fspInfo = Get-Item $fileSystempath
					if ($fspInfo -is [System.IO.DirectoryInfo])
					{
						<#
							Item is a directory; inspect directory (possibly with recursion)
							Note: dependent on file extensions
							Get-AppLockerFileInformation -Directory inspects files with these extensions:
							.com, .exe, .dll, .ocx, .msi, .msp, .mst, .bat, .cmd, .js, .ps1, .vbs, .appx
							But this script drops .msi, .msp, .mst, and .appx
						#>
						Get-AppLockerFileInformation -Directory $fileSystempath @paramGetAppLockerFileInformation | Add-Policy -Policies $policies -Prefix $RuleNamePrefix
					}
					elseif ($fspInfo -is [System.IO.FileInfo])
					{
						# Item is a file; get applocker information for the file
						Get-AppLockerFileInformation -Path $fileSystempath | Add-Policy -Policies $policies -Prefix $RuleNamePrefix
					}
					else
					{
						# Specified object exists and is not a file or a directory.
						# Display a warning but continue.
						Write-Warning -Message ("Unexpected object type for {0} : {1}" -f $fileSystempath, $fspInfo.GetType().FullName)
					}
				}
				else
				{
					# Specified object does not exist.
					# Display a warning but continue.
					Write-Warning -Message "FILE SYSTEM OBJECT DOES NOT EXIST: $fileSystempath"
				}
			}
		}
		#endregion Process all specified paths and build the policies dictionary
	}
	end
	{
		if ($policies.Count -eq 0) { Write-Warning "No policies generated, no file found after scanning $($countItems) paths" }
		$policies.Values
	}
}