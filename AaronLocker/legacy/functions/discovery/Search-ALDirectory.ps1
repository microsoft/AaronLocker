#TODO: Cleanup Path references once scan-caching issue is resolved satisfactorily.



function Search-ALDirectory
{
<#
	.SYNOPSIS
		Scan directories to identify files that might need additional AppLocker rules.
	
	.DESCRIPTION
		Produces a list of files in various directories that might need additional AppLocker rules to allow them to execute.
		Optionally, the script can list non-standard directories in the %SystemDrive% root directory. These directories might require additional scanning.
		
		The script searches specified directory hierarchies for MSIs and scripts (according to file extension), and EXE/DLL files regardless of extension.
		That is, a file can be identified as a Portable Executable (PE) file (typically an EXE or DLL) even if it has a non-standard extension or no extension.
		
		Output columns include:
		* IsSafeDir - indicates whether the file's parent directory is "safe" (not user-writable) or "unsafe" (user-writable);
		* File type - EXE/DLL, MSI, or Script;
		* File extension - the file's extension;
		* File name - the file name without path information;
		* File path - Full path to the file;
		* Parent directory - The file's parent directory;
		* Publisher name, Product name - signature and product name that can be used in publisher rules;
		* CreationTime, LastAccessTime, LastWriteTime - the file's timestamps according to the file system.
		
		Directories that can be searched:
		* WritableWindir - writable subdirectories of the %windir% directory, based on results of the last scan performed by Create-Policies.ps1;
		* WritablePF - writable subdirectories of the %ProgramFiles% directories, based on results of the last scan performed by Create-Policies.ps1;
		* SearchProgramData - the %ProgramData% directory hierarchy;
		* SearchOneUserProfile - the current user's profile directory;
		* SearchAllUserProfiles - the root directory of user profiles (C:\Users);
		* DirsToSearch - one or more caller-specified, comma-separated directory paths.
		
		Note that results from this script do not necessarily require that rules be created:
		this is just an indicator about files that *might* need rules, if the files need to be allowed.
	
	.PARAMETER WritableWindir
		If this switch is specified, searches user-writable subdirectories under %windir% according to results of the last scan performed by Create-Policies.ps1.
	
	.PARAMETER WritablePF
		If this switch is specified, searches user-writable subdirectories under the %ProgramFiles% directories according to results of the last scan performed by Create-Policies.ps1.
	
	.PARAMETER SearchProgramData
		If this switch is specified, searches the %ProgramData% directory hierarchy, which can contain a mix of "safe" and "unsafe" directories.
	
	.PARAMETER SearchOneUserProfile
		If this switch is specified, searches the user's profile directory.
	
	.PARAMETER SearchAllUserProfiles
		If this switch is specified, searches from the root directory of all users' profiles (C:\Users)
	
	.PARAMETER DirsToSearch
		Specifies one or more directories to search.
	
	.PARAMETER NoPEFiles
		If this switch is specified, does not search for Portable Executable files (EXE/DLL files)
	
	.PARAMETER NoScripts
		If this switch is specified, does not search for script files.
	
	.PARAMETER NoMSIs
		If this switch is specified, does not search for MSI files.
	
	.PARAMETER DirectoryNamesOnly
		If this switch is specified, reports the names and "safety" of directories that contain files of interest but no file information.
	
	.PARAMETER FindNonDefaultRootDirs
		If this switch is specified, identifies non-standard directories in the %SystemDrive% root directory.
		These directories often contain LOB applications.
		This switch cannot be used with any other options.
	
	.EXAMPLE
		PS C:\> Search-ALDirectory -SearchOneUserProfile -DirsToSearch H:\
		
		Searches the user's profile directory and the H: drive.
	
	.NOTES
		#TODO: Find a way to miss the .js false-positives, including but not only in browser caches.
		#TODO: Skip .js in browser temp caches (IE on Win10: localappdata\Microsoft\Windows\INetCache) - possibly obviated by not looking at .js
		#TODO: Maybe offer an option not to exclude .js; could be useful outside of user profiles? Maybe include .js for some directory types and not others.
		#TODO: Distinguish between Exe and Dll files based on IMAGE_FILE_HEADER characteristics.
#>
	[CmdletBinding()]
	param (
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$WritableWindir,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$WritablePF,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$SearchProgramData,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$SearchOneUserProfile,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$SearchAllUserProfiles,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[String[]]
		$DirsToSearch,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$NoPEFiles,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$NoScripts,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$NoMSIs,
		
		[parameter(ParameterSetName = "SearchDirectories")]
		[switch]
		$DirectoryNamesOnly,
		
		[parameter(ParameterSetName = "NonDefaultRootDirs")]
		[switch]
		$FindNonDefaultRootDirs
	)
	
	begin
	{
		Set-StrictMode -Version Latest
		
		if (-not $FindNonDefaultRootDirs)
		{
			if (-not (Test-AccessChk))
			{
				throw @"
Scanning for writable subdirectories requires that Sysinternals AccessChk.exe be available.
Please download it and use Set-ALConfiguration -PathAccessChk "<path>" to register its location.
"AccessChk.exe was not found. Exiting...
"@
			}
		}
		
		#region Utility Functions
		function Search-File
		{
			[CmdletBinding()]
			param (
				[string]
				$Directory,
				
				[string]
				$Safety,
				
				[string[]]
				$WritableDirs
			)
			$doNoMore = $false
			
			Get-ChildItem -File $Directory -Force -ErrorAction SilentlyContinue -PipelineVariable file | ForEach-Object {
				
				# Work around Get-AppLockerFileInformation bug that vomits on zero-length input files
				if ($_.Length -gt 0 -and -not $doNoMore)
				{
					$filetype = $null
					if ((-not $NoScripts) -and ($file.Extension -in $scriptExtensions))
					{
						$filetype = "Script"
					}
					elseif ((-not $NoMSIs) -and ($file.Extension -in $msiExtensions))
					{
						$filetype = "MSI"
					}
					elseif ((-not $NoPEFiles) -and (Test-FileExecutable -File $file))
					{
						$filetype = "EXE/DLL"
					}
					
					# Output
					if ($null -ne $filetype)
					{
						$fullname = $file.FullName
						$fileext = $file.Extension
						$filename = $file.Name
						$parentDir = [System.IO.Path]::GetDirectoryName($fullname)
						$pubName = $prodName = [String]::Empty
						$alfi = Get-AppLockerFileInformation $file.FullName -ErrorAction SilentlyContinue -ErrorVariable alfiErr
						# Diagnostics. Seeing sharing violations on some operations
						if ($alfiErr.Count -gt 0)
						{
							Write-Host ($file.FullName + "`tLength = " + $file.Length.ToString()) -ForegroundColor Yellow -BackgroundColor Black
							$alfiErr | ForEach-Object { Write-Host $_.Exception -ForegroundColor Red -BackgroundColor Black }
						}
						if ($null -ne $alfi)
						{
							$pub = $alfi.Publisher
							if ($null -ne $pub)
							{
								$pubName = $pub.PublisherName
								$prodName = $pub.ProductName
							}
						}
						$safetyOut = $Safety
						if ($Safety -eq $UnknownDir)
						{
							#$dbgInfo = $fullname + "`t" + $parentDir
							if ($parentDir -in $WritableDirs)
							{
								#$dbgInfo = $UnsafeDir + "`t" + $dbgInfo
								$safetyOut = $UnsafeDir
							}
							else
							{
								#$dbgInfo = ($SafeDir + "`t" + $dbgInfo)
								$safetyOut = $SafeDir
							}
							#$dbgInfo
						}
						
						if ($DirectoryNamesOnly)
						{
							[pscustomobject]@{
								PSTypeName      = "AaronLocker.Detection.Directory"
								IsSafeDir	    = $safetyOut
								ParentDirectory = $parentDir
							}
							
							# Found one file - don't need to continue inspection of files in this directory
							$doNoMore = $true
						}
						else
						{
							[pscustomobject]@{
								PSTypeName	    = "AaronLocker.Detection.File"
								IsSafeDir	    = $safetyOut
								FileType	    = $filetype
								FileExtension   = $fileext
								FileName	    = $filename
								FilePath	    = $fullname
								ParentDirectory = $parentDir
								PublisherName   = $pubName
								ProductName	    = $prodName
								CreationTime    = $file.CreationTime
								LastAccessTime  = $file.LastAccessTime
								LastWriteTime   = $file.LastWriteTime
							}
						}
					}
				}
			}
		}
		
		function Search-Directory
		{
			[CmdletBinding()]
			param (
				[string]
				$Directory,
				
				[string]
				$Safety,
				
				[string[]]
				$WritableDirs
			)
			Search-File -Directory $Directory -Safety $Safety -WritableDirs $WritableDirs
			
			Get-ChildItem -Directory $Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
				$subdir = $_
				# Decide here whether to recurse into the subdirectory:
				# * Skip junctions and symlinks (typically app-compat junctions).
				# * Can add criteria here to skip browser caches, etc.
				if (-not ($subdir.Attributes -band ([System.IO.FileAttributes]::ReparsePoint)))
				{
					Write-Verbose "... $($subdir.FullName)"
					Search-Directory -Directory $subdir.FullName -Safety $Safety -WritableDirs $WritableDirs
				}
				else
				{
					Write-Verbose "SKIPPING $($subdir.FullName)"
				}
			}
		}
		
		function Test-FileExecutable
		{
		<#
			.SYNOPSIS
				Inspect files for PE properties
			
			.DESCRIPTION
				Inspect files for PE properties (on the cheap!)
				If it's 64 bytes or more, and the first two are "MZ", we're calling it a PE file.
			
			.PARAMETER File
				The file to inspect
			
			.EXAMPLE
				PS C:\> Test-FileExecutable -File $file
			
				Checks whether $file is an executable
		#>
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[System.IO.FileInfo]
				$File
			)
			
			if ($File.Length -lt 64)
			{
				return $false
			}
			
			$mzHeader = Get-Content -LiteralPath $File.FullName -TotalCount 2 -Encoding Byte -ErrorAction SilentlyContinue
			
			# 0x4D = 'M', 0x5A = 'Z'
			return $null -ne $mzHeader -and ($mzHeader[0] -eq 0x4D -and $mzHeader[1] -eq 0x5A)
		}
		#endregion Utility Functions
		
		# ".js", ### Too many false positives; these are almost always executed within programs that do not restrict .js.
		$scriptExtensions = @(
			".bat",
			".cmd",
			".vbs",
			".wsf",
			".wsh",
			".ps1"
		)
		$msiExtensions = @(
			".msi",
			".msp",
			".mst"
		)
	}
	
	process
	{
		#region Find Non-Default root directories
		### ======================================================================
		### The FindNonDefaultRootDirs is a standalone option that cannot be used with other switches. 
		### It searches the SystemDrive root directory and enumerates non-default directory names.
		if ($FindNonDefaultRootDirs)
		{
			$defaultRootDirs = @(
				'$Recycle.Bin',
				'Config.Msi',
				'MSOTraceLite',
				'OneDriveTemp',
				'PerfLogs',
				'Program Files',
				'Program Files (x86)',
				'ProgramData',
				'Recovery',
				'System Volume Information',
				'Users',
				'Windows'
			)
			
			# Enumerate root-level directories whether hidden or not, but exclude junctions and symlinks.
			# Output the ones that don't exist in a default Windows installation.
			Get-ChildItem -Directory -Force "$($env:SystemDrive)\" |
			Where-Object { -not ($_.Attributes -band ([System.IO.FileAttributes]::ReparsePoint)) -and ($_ -notin $defaultRootDirs) } |
			Select-Object -ExpandProperty FullName
			
			return
		}
		#endregion Find Non-Default root directories
		
		#$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
		# Dot-source the config file.
		#. $rootDir\Support\Config.ps1
		<#
		Heathen Variables used:
		$windirTxt
		$PfTxt
		$Pf86Txt
		#>
		
		# Define some constants
		Set-Variable UnsafeDir -option Constant -value "UnsafeDir"
		Set-Variable SafeDir -option Constant -value "SafeDir"
		Set-Variable UnknownDir -option Constant -value "UnknownDir"
		
		# Hashtable: key is path to inspect; value is indicator whether safe/unsafe
		$dirsToInspect = @{ }
		
		# Writable directories under \Windows; known to be unsafe paths
		if ($WritableWindir)
		{
			if (-not (Test-Path -Path $windirTxt))
			{
				Write-Warning "$windirTxt does not exist yet. Run Create-Policies.ps1."
			}
			else
			{
				Get-Content $windirTxt | ForEach-Object {
					$dirsToInspect.Add($_, $UnsafeDir)
				}
			}
		}
		
		# Writable directories under ProgramFiles; known to be unsafe paths
		if ($WritablePF)
		{
			if (-not (Test-Path -Path $PfTxt))
			{
				Write-Warning "$PfTxt does not exist yet. Run Create-Policies.ps1."
			}
			elseif (-not (Test-Path -Path $Pf86Txt))
			{
				Write-Warning "$Pf86Txt does not exist yet. Run Create-Policies.ps1."
			}
			else
			{
				Get-Content $PfTxt, $Pf86Txt | ForEach-Object {
					$dirsToInspect.Add($_, $UnsafeDir)
				}
			}
		}
		
		if ($SearchProgramData)
		{
			# Probably a mix of safe and unsafe paths
			$dirsToInspect.Add($env:ProgramData, $UnknownDir)
		}
		
		if ($SearchOneUserProfile)
		{
			#Assume all unsafe paths
			#TODO: Skip browser-cache temp directories
			$dirsToInspect.Add($env:USERPROFILE, $UnsafeDir)
		}
		
		if ($SearchAllUserProfiles)
		{
			#Assume all unsafe paths
			# No special folder or environment variable available. Get root directory from parent directory of user profile directory
			$rootdir = [System.IO.Path]::GetDirectoryName($env:USERPROFILE)
			#TODO: Skip browser-cache temp directories
			# Skip app-compat juntions  (most disallow FILE_LIST_DIRECTORY)
			# Skip symlinks -- "All Users" is a symlinkd for \ProgramData but unlike most app-compat junctions it can be listed/traversed.
			# This code prevents that.
			Get-ChildItem -Force -Directory C:\Users | Where-Object { -not $_.Attributes -band ([System.IO.FileAttributes]::ReparsePoint) } | ForEach-Object {
				$dirsToInspect.Add($_.FullName, $UnsafeDir)
			}
		}
		
		if ($DirsToSearch)
		{
			$DirsToSearch | ForEach-Object { $dirsToInspect.Add($_, $UnknownDir) }
		}
		
		# Exclude known admins from analysis
		$knownAdmins = $script:config.KnownAdmins
		
		# Capture into hash tables, separate file name, type, and parent path
		$dirsToInspect.Keys | ForEach-Object {
			
			$dirToInspect = $_
			$safety = $dirsToInspect[$dirToInspect]
			if ($safety -eq $UnknownDir)
			{
				Write-Host "about to inspect $dirToInspect for writable directories..." -ForegroundColor Cyan
				$writableDirs = Search-WritableDirectory -RootDirectory $dirToInspect -KnownAdmins $knownAdmins
				if ($null -eq $writableDirs)
				{
					$writableDirs = @()
				}
			}
			else
			{
				$writableDirs = @()
			}
			
			Write-Host "About to inspect $dirToInspect..." -ForegroundColor Cyan
			Search-Directory -Directory $dirToInspect -Safety $safety -WritableDirs $writableDirs
		}
<# Informational:

    Get-AppLockerFileInformation -Directory searches for these file extensions:
        *.com
        *.exe
        *.dll
        *.ocx
        *.msi
        *.msp
        *.mst
        *.bat
        *.cmd
        *.js
        *.ps1
        *.vbs
        *.appx
#>
	}
}