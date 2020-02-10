<#
.SYNOPSIS
Scan directories to identify files that might need additional AppLocker rules.

.DESCRIPTION
Produces tab-delimited CSV or an Excel worksheet listing files in various directories that might need additional AppLocker rules to allow them to execute.
Optionally, the script can list non-standard directories in the %SystemDrive% root directory. These directories might require additional scanning.

The script searches specified directory hierarchies for MSIs and scripts (according to file extension), and EXE/DLL files regardless of extension. That is, a file can be identified as a Portable Executable (PE) file (typically an EXE or DLL) even if it has a non-standard extension or no extension.

Output columns include:
* IsSafeDir - indicates whether the file's parent directory is "safe" (not user-writable) or "unsafe" (user-writable);
* File type - EXE/DLL, MSI, or Script;
* File extension - the file's extension;
* File name - the file name without path information;
* File path - Full path to the file;
* Parent directory - The file's parent directory;
* Publisher name, Product name, Binary name, Version - signature and version resource information that can be used in publisher rules;
* Hash - the file's hash;
* CreationTime, LastAccessTime, LastWriteTime - the file's timestamps according to the file system;
* File size.

Directories that can be searched:
* WritableWindir - writable subdirectories of the %windir% directory, based on results of the last scan performed by Create-Policies.ps1;
* WritablePF - writable subdirectories of the %ProgramFiles% directories, based on results of the last scan performed by Create-Policies.ps1;
* SearchProgramData - the %ProgramData% directory hierarchy;
* SearchOneUserProfile - the current user's profile directory;
* SearchAllUserProfiles - the root directory of user profiles (C:\Users);
* DirsToSearch - one or more caller-specified, comma-separated directory paths.

Results can be imported into Microsoft Excel and analyzed.

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

.PARAMETER SearchNonDefaultRootDirs
If this switch is specified, search all non-standard directories in the %SystemDrive% root directory. These directories often contain LOB applications.

.PARAMETER DirsToSearch
Specifies one or more directories to search.

.PARAMETER NoPEFiles
If this switch is specified, does not search for Portable Executable files (EXE/DLL files)

.PARAMETER NoScripts
If this switch is specified, does not search for script files.

.PARAMETER NoMSIs
If this switch is specified, does not search for MSI files.

.PARAMETER JS
If this switch is specified, report .js files as script files; otherwise, skip .js files entirely.

.PARAMETER DirectoryNamesOnly
If this switch is specified, reports the names and "safety" of directories that contain files of interest but no file information.

.PARAMETER Excel
If this switch is specified, outputs to formatted Excel worksheet instead of to pipeline

.PARAMETER GridView
If this switch is specified, outputs to PowerShell GridView

.PARAMETER FindNonDefaultRootDirs
If this switch is specified, identifies non-standard directories in the %SystemDrive% root directory. These directories often contain LOB applications.
This switch cannot be used with any other options

.PARAMETER Verbose
Shows progress through directory scans, and other verbose diagnostics.


.EXAMPLE
Scan-Directories.ps1 -SearchOneUserProfile -DirsToSearch H:\

Searches the user's profile directory and the H: drive.

#>

#TODO: Need automation to turn selected results into rules.

param(
    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $WritableWindir = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $WritablePF = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $SearchProgramData = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $SearchOneUserProfile = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $SearchAllUserProfiles = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $SearchNonDefaultRootDirs = $false,

    [parameter(ParameterSetName="SearchDirectories", Mandatory=$false)]
	[String[]]
	$DirsToSearch,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $NoPEFiles = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $NoScripts = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $NoMSIs = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $JS = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $DirectoryNamesOnly = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $Excel = $false,

    [parameter(ParameterSetName="SearchDirectories")]
    [switch]
    $GridView = $false,

    [parameter(ParameterSetName="NonDefaultRootDirs")]
    [switch]
    $FindNonDefaultRootDirs = $false
)

### ======================================================================

Set-StrictMode -Version Latest


### ======================================================================
### The FindNonDefaultRootDirs is a standalone option that cannot be used with other switches. 
### It searches the SystemDrive root directory and enumerates non-default directory names.
### SearchNonDefaultRootDirs also uses that information.
$nondefaultRootDirs = $null
if ($FindNonDefaultRootDirs -or $SearchNonDefaultRootDirs)
{
    $defaultRootDirs =
        '$Recycle.Bin',
        'Config.Msi',
        'MSOCache',
        'MSOTraceLite',
        'OneDriveTemp',
        'PerfLogs',
        'Program Files',
        'Program Files (x86)',
        'ProgramData',
        'Recovery',
        'System Volume Information',
        'Users',
        'Windows',
        'Windows.old'

    # Enumerate root-level directories whether hidden or not, but exclude junctions and symlinks.
    # Output the ones that don't exist in a default Windows installation.
    $nondefaultRootDirs = (Get-ChildItem -Directory -Force ($env:SystemDrive + "\") | 
        Where-Object { !$_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) -and !($_ -in $defaultRootDirs) })

    if ($FindNonDefaultRootDirs)
    {
        $nondefaultRootDirs | foreach { $_.FullName }
        return
    }
}


### ======================================================================

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Dot-source the config file.
. $rootDir\Support\Config.ps1

# Define some constants
Set-Variable UnsafeDir  -option Constant -value "UnsafeDir"
Set-Variable SafeDir    -option Constant -value "SafeDir"
Set-Variable UnknownDir -option Constant -value "UnknownDir"


$scriptExtensions =
    ".bat",
    ".cmd",
    ".vbs",
    ".wsf",
    ".wsh",
    ".ps1"
# Include .js files only if specifically requested. Too many false positives otherwise; AppLocker restrictions applied only within Windows Script Host.
if ($JS)
{
    $scriptExtensions += ".js"
}
$MsiExtensions =
    ".msi",
    ".msp",
    ".mst"

# Hashtable: key is path to inspect; value is indicator whether safe/unsafe
$dirsToInspect = @{}

# Writable directories under \Windows; known to be unsafe paths
if ($WritableWindir)
{
    if (!(Test-Path($windirTxt)))
    {
        Write-Warning "$windirTxt does not exist yet. Run Create-Policies.ps1."
    }
    else
    {
        Get-Content $windirTxt | foreach {
            $dirsToInspect.Add($_, $UnsafeDir)
        }
    }
}

# Writable directories under ProgramFiles; known to be unsafe paths
if ($WritablePF)
{
    if (!(Test-Path($PfTxt)))
    {
        Write-Warning "$PfTxt does not exist yet. Run Create-Policies.ps1."
    }
    elseif (!(Test-Path($Pf86Txt)))
    {
        Write-Warning "$Pf86Txt does not exist yet. Run Create-Policies.ps1."
    }
    else
    {
        Get-Content $PfTxt, $Pf86Txt | foreach {
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
    $dirsToInspect.Add($env:USERPROFILE, $UnsafeDir)
}

if ($SearchAllUserProfiles)
{
    #Assume all unsafe paths
    # No special folder or environment variable available. Get user-profiles' root directory from the parent directory of the "all users" profile directory
    $UsersRoot = [System.IO.Path]::GetDirectoryName($env:PUBLIC)
    # Skip app-compat juntions  (most disallow FILE_LIST_DIRECTORY)
    # Skip symlinks -- "All Users" is a symlinkd for \ProgramData but unlike most app-compat junctions it can be listed/traversed.
    # This code prevents that.
    Get-ChildItem -Force -Directory $UsersRoot | Where-Object { !$_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) } | foreach {
        $dirsToInspect.Add($_.FullName, $UnsafeDir)
    }
}

if ($SearchNonDefaultRootDirs)
{
    $nondefaultRootDirs | foreach { $dirsToInspect.Add($_.FullName, $UnknownDir) }
}

if ($DirsToSearch)
{
    $DirsToSearch | foreach { $dirsToInspect.Add($_, $UnknownDir) }
}

[System.Collections.ArrayList]$csv = @()

# Output column headers
if ($DirectoryNamesOnly)
{
    $csv.Add(
        "IsSafeDir" + "`t" + 
        "Parent directory") | Out-Null
}
else
{
    $csv.Add(
        "IsSafeDir" + "`t" + 
        "File type" + "`t" + 
        "File extension" + "`t" +
        "File name" + "`t" +
        "File path" + "`t" + 
        "Parent directory" + "`t" +
        "Publisher name" + "`t" +
        "Product name" + "`t" +
        "Binary name" + "`t" +
        "Version" + "`t" +
        "Hash" + "`t" +
        "CreationTime" + "`t" +
        "LastAccessTime" + "`t" +
        "LastWriteTime" + "`t" +
        "File size" ) | Out-Null
}


function InspectFiles([string]$directory, [string]$safety, [ref] [string[]]$writableDirs)
{
    $doNoMore = $false

    # Don't waste cycles looking at file types that are not of interest. (A .txt should never be a PE...)
    Get-ChildItem -File $directory -Force -ErrorAction SilentlyContinue -PipelineVariable file | 
    Where-Object { $file.Extension -notin $NeverExecutableExts } |
    foreach {

        # Work around Get-AppLockerFileInformation bug that vomits on zero-length input files
        if ($_.Length -gt 0 -and !$doNoMore)
        {
            $filetype = $null
            if ((!($NoScripts)) -and ($file.Extension -in $scriptExtensions))
            {
                $filetype = "Script"
            }
            elseif ((!($NoMSIs)) -and ($file.Extension -in $MsiExtensions))
            {
                $filetype = "MSI"
            }
            # Don't waste cycles inspecting .js files here if they haven't been evaluated.
            elseif (!($NoPEFiles) -and ($file.Extension -ne ".js"))
            {
                $filetype = IsWin32Executable($file.FullName)
            }

            # Output
            if ($null -ne $filetype)
            {
                $fullname = $file.FullName
                $fileext = $file.Extension
                $filename = $file.Name
                $parentDir = [System.IO.Path]::GetDirectoryName($fullname)
                $pubName = $prodName = $binName = $binVer = [String]::Empty
                $alfi = Get-AppLockerFileInformation $file.FullName -ErrorAction SilentlyContinue -ErrorVariable alfiErr
                # Diagnostics. Seeing sharing violations on some operations
                if ($alfiErr.Count -gt 0)
                {
                    Write-Host ($file.FullName + "`tLength = " + $file.Length.ToString()) -ForegroundColor Yellow -BackgroundColor Black
                    $alfiErr | foreach { Write-Host $_.Exception -ForegroundColor Red -BackgroundColor Black}
                }
                if ($null -ne $alfi)
                {
                    $pub = $alfi.Publisher
                    if ($null -ne $pub)
                    {
                        $pubName = $pub.PublisherName
                        $prodName = $pub.ProductName
                        $binName = $pub.BinaryName
                        $binVer = $pub.BinaryVersion
                    }
                    $hash = $alfi.Hash.HashDataString
                }
                $safetyOut = $safety
                if ($safety -eq $UnknownDir)
                {
                    #$dbgInfo = $fullname + "`t" + $parentDir
                    if ($parentDir -in $writableDirs.Value)
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
                    $safetyOut + "`t" + 
                    $parentDir

                    # Found one file - don't need to continue inspection of files in this directory
                    $doNoMore = $true
                }
                else
                {
                    $safetyOut + "`t" + 
                    $filetype + "`t" + 
                    $fileext + "`t" + 
                    $filename + "`t" + 
                    $fullname + "`t" + 
                    $parentDir + "`t" + 
                    $pubName + "`t" +
                    $prodName + "`t" +
                    $binName + "`t" +
                    $binVer + "`t" +
                    $hash + "`t" +
                    $file.CreationTime + "`t" + 
                    $file.LastAccessTime  + "`t" + 
                    $file.LastWriteTime + "`t" +
                    $file.Length
                }
            }
        }
    }
}

function InspectDirectories([string]$directory, [string]$safety, [ref][string[]]$writableDirs)
{
    InspectFiles $directory $safety $writableDirs

    Get-ChildItem -Directory $directory -Force -ErrorAction SilentlyContinue | foreach {
        $subdir = $_
        # Decide here whether to recurse into the subdirectory:
        # * Skip junctions and symlinks (typically app-compat junctions).
        # * Can add criteria here to skip browser caches, etc.
        if (!$subdir.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint))
        {
            Write-Verbose ("... subdir " + $subdir.FullName)
            InspectDirectories $subdir.FullName $safety $writableDirs
        }
        else
        {
            Write-Verbose ("SKIPPING " + $subdir.FullName)
        }
    }
}


# Scanning requires that AccessChk.exe be available.
# If accesschk.exe is in the rootdir, temporarily add the rootdir to the path.
# (Previous implementation invoked Get-Command to see whether accesschk.exe was in the path, and only if that failed looked for
# accesschk.exe in the rootdir. However, there was no good way to keep Get-Command from displaying a "Suggestion" message in that
# scenario.)
# Variable for restoring original Path, if necessary.
$origPath = ""
# Check for accesschk.exe in the rootdir.
if (Test-Path -Path $rootDir\AccessChk.exe)
{
    # Found it in this script's directory. Temporarily prepend it to the path.
    $origPath = $env:Path
    $env:Path = "$rootDir;" + $origPath
}

# Exclude known admins from analysis
[System.Collections.ArrayList]$knownAdmins = @()
$knownAdmins.AddRange( @(& $ps1_KnownAdmins) )

# Capture into hash tables, separate file name, type, and parent path
$dirsToInspect.Keys | foreach {

    $dirToInspect = $_
    $safety = $dirsToInspect[$dirToInspect]
    if ($safety -eq $UnknownDir)
    {
        Write-Host "about to inspect $dirToInspect for writable directories..." -ForegroundColor Cyan
        if ((Get-Command AccessChk.exe -ErrorAction SilentlyContinue) -eq $null)
        {
            $errMsg = "Scanning for writable subdirectories requires that Sysinternals AccessChk.exe be in the Path or in the same directory with this script.`n" +
                "AccessChk.exe was not found.`n" +
                "(See .\Support\DownloadAccesschk.ps1 for help.)`n" +
                "Exiting..."
            Write-Error $errMsg
            return
        }
        $writableDirs = [ref] ( & $ps1_EnumWritableDirs -RootDirectory $dirToInspect -KnownAdmins $knownAdmins)
        if ($null -eq $writableDirs)
        {
            $writableDirs = [ref]@()
        }
    }
    else
    {
        $writableDirs = [ref]@()
    }

    Write-Host "About to inspect $dirToInspect..." -ForegroundColor Cyan
    $csv.AddRange( @(InspectDirectories $dirToInspect $safety $writableDirs) )
}

# Restore original Path if it was altered for AccessChk.exe
if ($origPath.Length -gt 0)
{
    $env:Path = $origPath
}


if ($Excel)
{
    $OutputEncodingPrevious = $OutputEncoding
    $OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

    $tempfile = [System.IO.Path]::GetTempFileName()

    $tabname = "Consider for potential rules"

    $csv | Out-File $tempfile -Encoding unicode

    CreateExcelFromCsvFile $tempfile $tabname # $linebreakSeq

    Remove-Item $tempfile

    $OutputEncoding = $OutputEncodingPrevious
}
elseif ($GridView)
{
    $csv | ConvertFrom-Csv -Delimiter "`t" | Out-GridView -Title $MyInvocation.MyCommand.Name
}
else
{
    # Just output the CSV raw
    $csv
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