<#
.SYNOPSIS
Builds tightly-scoped but forward-compatible AppLocker rules for files in user-writable directories. The rules are intended to be merged into a larger set using Create-Policies.ps1 in the root directory.

TODO: Handle files with non-standard extensions, especially EXE and DLL files. And distinguish EXE and DLLs (without relying on extension)
TODO: If pubOnly specified and a signed file is missing version information, generate a publisher rule instead of a hash rule.

.DESCRIPTION
This script takes a list of one or more file system objects (files and/or directories) and generates rules to allow execution of the corresponding files.

Rule files generated with this script can be incorporated into comprehensive rule sets using Create-Policies.ps1 in the root directory.

Publisher rules are generated where possible:
* Publisher rules restrict to a specific publisher, product name, binary name, and minimum file version. Optionally, less-granular rules can be generated (e.g., publisher only, publisher/product only, etc.)
* Redundant rules are removed; if multiple versions of a specific file are found, the rule allows execution of the lowest-identified version or above.
Hash rules are generated when publisher rules cannot be created.
The script creates rule names and descriptions designed for readability in the Security Policy editor. The RuleNamePrefix option enables you to give each rule in the set a common prefix (e.g., "OneDrive") to make the source of the rule more apparent and so that related rules can be grouped alphabetically by name.
The rules' EnforcementMode is left NotConfigured. (Create-Policies.ps1 takes care of setting EnforcementMode in the larger set.)

File system objects can be identified on the command line with -FileSystemPaths, or listed in a file (one object per line) referenced by -FileOfFileSystemObjects.

This script determines whether each object is a file or a directory. For directories, this script enumerates and identifies EXE, DLL, and Script files based on file extension. Subdirectories are scanned if the -RecurseDirectories switch is specified on the command line.

The intent of this script is to create fragments of policies that can be incorporated into a "master" policy in a modular way. For example, create a file representing the rules needed to allow OneDrive to run, and separate files for LOB apps. If/when the OneDrive rules need to be updated, they can be updated in isolation and those results incorporated into a new master set.


.PARAMETER FileSystemPaths
An array of file paths and/or directory paths to scan. The array can be a comma-separated list of file system paths.
Either FileSystemPaths or FileOfFileSystemPaths must be specified.

.PARAMETER FileOfFileSystemPaths
The name of a file containing a list of file paths and/or directory paths to scan; one path to a line.
Either FileSystemPaths or FileOfFileSystemPaths must be specified.

.PARAMETER RecurseDirectories
If this switch is specified, scanning of directories includes subdirectories; otherwise, only files in the named directory are scanned.

.PARAMETER PubRuleGranularity
Optional parameter to specify the granularity of generated publisher rules. If specified, must be one of the following:
* pubOnly - lowest granularity: Publisher rules specify publisher only
* pubProduct - Publisher rules specify publisher and product
* pubProductBinary - (default) Publisher rules specify publisher, product, and binary name
* pubProdBinVer - highest granularity: Publisher rules specify publisher, product, binary name, and minimum version.
Note that Microsoft-signed Windows and Visual Studio files are always handled at a minimum granularity of "pubProductBinary";
other Microsoft-signed files are handled at a minimum granularity of "pubProduct".

.PARAMETER OutputPubFileName
Required: the name/path of the XML output file containing the generated publisher rules.

.PARAMETER OutputHashFileName
Required: the name/path of the XML output file containing the generated hash rules.

.PARAMETER RuleNamePrefix
Optional: If specified, all rule names begin with the specified RuleNamePrefix.

.EXAMPLE
.\BuildRulesForFilesInWritableDirectories.ps1 -FileSystemPaths $env:LOCALAPPDATA\Microsoft\OneDrive -RecurseDirectories -RuleNamePrefix OneDrive -OutputPubFileName ..\WorkingFiles\OneDrivePubRules.xml -OutputHashFileName ..\WorkingFiles\OneDriveHashRules.xml

Scans the OneDrive directory and subdirectories in the current user's profile.
All generated rule names will begin with "OneDrive".
The generated publisher rules are written to ..\WorkingFiles\OneDrivePubRules.xml and the generated hash rules to ..\WorkingFiles\OneDriveHashRules.xml.
Publisher rules created with default granularity (one rule per file).

#>

####################################################################################################
# Parameters
####################################################################################################


# Must use FileSystemPaths or FileOfFileSystemPaths; you can use RecurseDirectories with either.
param(
	# Comma-separated file paths and/or directory paths
	[parameter(Mandatory=$true, ParameterSetName="OnCommandLine")]
	[String[]]
	$FileSystemPaths,

    # Path to a file containing a list of file paths and/or directory paths
    [parameter(Mandatory=$true, ParameterSetName="SpecifiedInFile")]
    [String]
    $FileOfFileSystemPaths,

    # If specified, directories are recursed
    [switch]
    $RecurseDirectories,

    # Granularity of publisher rules generated by this script.
    [parameter(Mandatory=$false)]
    [ValidateSet("pubOnly", "pubProduct", "pubProductBinary", "pubProdBinVer")]
    [String]
    $PubRuleGranularity = "pubProductBinary",

    # Name of output file for publisher rules
    [parameter(Mandatory=$true)]
    [String]
    $OutputPubFileName,

    # Name of output file for hash rules
    [parameter(Mandatory=$true)]
    [String]
    $OutputHashFileName,

    # Optional prefix incorporated into each rule name
    [parameter(Mandatory=$false)]
    [String]
    $RuleNamePrefix
)

####################################################################################################
# Initialize
####################################################################################################

# Depends on global support functions
$thisDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
. $thisDir\SupportFunctions.ps1

# Build an absolute path for the output file names
if (![System.IO.Path]::IsPathRooted($OutputPubFileName))
{
    $OutputPubFileName = [System.IO.Path]::Combine($thisDir, $OutputPubFileName)
}
if (![System.IO.Path]::IsPathRooted($OutputHashFileName))
{
    $OutputHashFileName = [System.IO.Path]::Combine($thisDir, $OutputHashFileName)
}

# Files/directories to scan are on the command line (FileSystemPaths) or listed in a file (FileOfFileSystemPaths).
# If the latter, populate $FileSystemPaths from that file.
# Otherwise, $FileSystemPaths is already populated.
if ($FileOfFileSystemPaths.Length -gt 0)
{
    # Test path of the file name, verify that it's a file
    if ((Test-Path $FileOfFileSystemPaths) -and ((Get-Item $FileOfFileSystemPaths) -is [System.IO.FileInfo]))
    {
        $FileSystemPaths = Get-Content $FileOfFileSystemPaths
    }
    else
    {
        Write-Error -Category InvalidArgument -Message "`nINVALID FILE PATH: $FileOfFileSystemPaths"
        return
    }
}

# If RuleNamePrefix specified, append ": " to it before incorporating into rule names
if ($RuleNamePrefix.Length -gt 0)
{
    $RuleNamePrefix += ": "
}

$pubRuleInclProduct = $true
$pubRuleInclBinname = $true
$pubRuleInclMinver = $false
switch ($PubRuleGranularity)
{
    "pubOnly" 
    { 
        $pubRuleInclProduct = $pubRuleInclBinname = $false 
    }
    "pubProduct"
    {
        $pubRuleInclBinname = $false
    }
    "pubProductBinary"
    {
        # already default
    }
    "pubProdBinVer"
    {
        $pubRuleInclMinVer = $true
    }
    # This catch-all here in case the parameter ValidateSet attribute changes and this block doesn't...
    default
    {
        Write-Error -Category InvalidArgument -Message "`nINVALID PubRuleGranularity: $PubRuleGranularity"
        return
    }
}

# Array of AppLocker File Information objects
$arrALFI = @()
# Hash table of rules with redundant entries removed
$pubPolicies = @{}
$hashPolicies = @{}

# Marker that might need to be inserted temporarily into a file name.
Set-Variable filenameMarker -Option Constant -Value "24B311FED57A7997715E4."

####################################################################################################
# Gather file information
####################################################################################################

# Build the array of AppLocker File Information objects
foreach($fsp in $FileSystemPaths)
{
    # E.g., in case of blank lines in input file
    $fsp = $fsp.Trim()
    if ($fsp.Length -gt 0)
    {
        if (Test-Path $fsp)
        {
            # Determine whether directory or file
            $fspInfo = Get-Item $fsp -Force
            if ($fspInfo -is [System.IO.DirectoryInfo])
            {
                # Item is a directory; inspect directory (possibly with recursion)
                # Note: dependent on file extensions
                # Get-AppLockerFileInformation -Directory inspects files with these extensions:
                # .com, .exe, .dll, .ocx, .msi, .msp, .mst, .bat, .cmd, .js, .ps1, .vbs, .appx
                # But this script drops .msi, .msp, .mst, and .appx
                # filesNotInspected are the files Get-AppLockerFileInformation -Directory ignored.
                # If any of them are Win32 exe/dll files, pick them up too
                $filesNotInspected = @()
                # Don't need to look at files with these extensions - already looked at
                $extsToIgnore = ".com", ".exe", ".dll", ".ocx", ".msi", ".msp", ".mst", ".bat", ".cmd", ".js", ".ps1", ".vbs", ".appx"
                # Additional extensions that can be assumed not to be PE files; save time by not opening and inspecting them.
                $extsToIgnore += 
                    ".admx", ".adml", ".etl", ".evtx", 
                    ".gif", ".jpg", ".jpeg", ".png", ".svg", ".ico", ".pfm", ".ttf", ".fon", ".otf", ".cur",
                    ".html", ".htm", ".hta", ".css", 
                    ".txt", ".log", ".xml". ".xsl", ".ini",
                    ".pdf", ".tif", ".tiff", 
                    ".lnk", ".url", ".inf",
                    ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
                    ".zip", ".7z"
                if ($RecurseDirectories)
                {
                    $arrALFI += Get-AppLockerFileInformation -FileType Exe,Dll,Script -Directory $fsp -Recurse
                    # Get all files with extensions that haven't been inspected. (Would have used -Exclude with gci but it doesn't interact well with -File - bug?)
                    $filesNotInspected = Get-ChildItem -Recurse -Path $fsp -Force -File | 
                        Where-Object { $_.Extension -notin $extsToIgnore }
                }
                else
                {
                    $arrALFI += Get-AppLockerFileInformation -FileType Exe,Dll,Script -Directory $fsp
                    # Get all files with extensions that haven't been inspected. (Would have used -Exclude with gci but it doesn't interact well with -File - bug?)
                    $filesNotInspected = Get-ChildItem -Path $fsp -Force -File | 
                        Where-Object { $_.Extension -notin $extsToIgnore }
                }
                # Look at all the files not yet inspected and capture information for those that are Win32 EXE/DLLs with non-standard extensions.
                foreach( $fileToInspect in $filesNotInspected )
                {
                    # If IsWin32Executable returns "EXE" or "DLL" here it means it's a Win32 PE with a non-standard extension
                    $StdPeExt = IsWin32Executable($fileToInspect.FullName)
                    if ($null -ne $StdPeExt)
                    {
                        # We can get the AppLocker file information, but without a recognized extension, New-AppLockerPolicy
                        # won't know what collection to put it in. Fake it out by adjusting the Path attribute until after the
                        # rule is generated, then set it back.
                        $alfi = Get-AppLockerFileInformation -Path $fileToInspect.FullName
                        # Temporarily add the standard extension after an identifiable marker that we can remove later.
                        $alfi.Path.Path += $filenameMarker + $StdPeExt
                        # Now add it to the collection of AppLockerFileInformation objects to build rules for.
                        $arrALFI += $alfi
                    }
                }
            }
            elseif ($fspInfo -is [System.IO.FileInfo])
            {
                # Item is a file; get applocker information for the file
                $arrALFI += Get-AppLockerFileInformation -Path $fsp
            }
            else
            {
                # Specified object exists and is not a file or a directory.
                # Display a warning but continue.
                $msg = "UNEXPECTED OBJECT TYPE FOR $fsp`n" + $fspInfo.GetType().FullName
                Write-Warning -Message $msg
            }
        }
        else
        {
            # Specified object does not exist.
            # Display a warning but continue.
            Write-Warning -Message "FILE SYSTEM OBJECT DOES NOT EXIST: $fsp"
        }
    }
}

# If no valid items captured, quit now.
if ($arrALFI.Length -eq 0)
{
    Write-Warning -Message "NO FILES SCANNED."
    return
}

####################################################################################################
# Build rules
####################################################################################################

# Convert the AppLockerFileInformation objects into AppLockerPolicy objects.
# Add them to collection if duplicate information not already present.
foreach($alfi in $arrALFI)
{
    # If it's a signed file but ends up with a hash rule, put something in the description
    $signedFile = ($null -ne $alfi.Publisher)
    $MSSigned = $MSHighGranularity = $false
    $pubname = [string]::Empty
    if ($signedFile)
    {
        $pubname = $alfi.Publisher.PublisherName
        # Microsoft-signed requires at least product name in the publisher rule
        $MSSigned = $pubname.ToLower().Contains("microsoft")
        if ($MSSigned)
        {
            # Microsoft-signed Windows and Visual Studio files require greater granularity
            $msprodname = $alfi.Publisher.ProductName.ToLower()
            $MSHighGranularity = (
                ($msprodname.Contains("windows") -and $msprodname.Contains("operating system")) -or
                ($msprodname.Contains("visual studio"))
            )
        }
    }

    # Favor publisher rule; hash rule otherwise
    $pol = New-AppLockerPolicy -FileInformation $alfi -RuleType Publisher,Hash

    # Remove any temporary edit from the path name that was needed to get New-AppLockerPolicy to put it in the correct rule collection.
    # Need to restore it for the rule descriptions.
    $ixMarker = $alfi.Path.Path.IndexOf($filenameMarker)
    if ($ixMarker -gt 0)
    {
        $alfi.Path.Path = $alfi.Path.Path.Substring(0, $ixMarker)
    }

    foreach ($ruleCollection in $pol.RuleCollections)
    {
        $rtype = $ruleCollection.RuleCollectionType
        foreach($rule in $ruleCollection)
        {
            # Publisher rule - file is signed and has required PE version information
            if ($rule -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule])
            {
                $pubInfo = $rule.PublisherConditions
                # If checking versions, always allow newer
                $pubInfo.BinaryVersionRange.HighSection = $null
                
                # Build key based on how granular these rules are going to be.
                # Don't put version number into key; if version used, merge rules for same file
                # Put rule type and publisher name into the key
                $key = $rtype + "|" + $pubname
                # If MS-signed, have to be more granular than publisher-only
                if ($pubRuleInclProduct -or $MSSigned)
                {
                    # Add product name into the key
                    $key += "|" + $pubInfo.ProductName

                    # Some MS-signed have to be more granular than publisher/product-only and must have filename
                    if ($pubRuleInclBinname -or $MSHighGranularity)
                    {
                        # File-specific rules: add binary name to key
                        $key = "|" + $pubInfo.BinaryName

                        # File-specific name/description including full path
                        $rule.Name = $RuleNamePrefix + $pubInfo.BinaryName
                        $rule.Description = 
                            "Product: " + $pubInfo.ProductName + "`r`n" + 
                            "Publisher: " + $pubname + "`r`n" + 
                            "Original path: " + $alfi.Path.Path

                        if ($pubRuleInclMinver)
                        {
                            # Allow scanned version and above
                            $rule.Name += ", v" + $pubInfo.BinaryVersionRange.LowSection.ToString() + " and above"
                            # Check whether there's another rule for this file; pick rule with lowest version
                        }
                        else
                        {
                            $pubInfo.BinaryVersionRange.LowSection = $null
                        }
                    }
                    else
                    {
                        # NOT file-specific; publisher or publisher/product only
                        $pol.RuleCollections.PublisherConditions.BinaryName = "*"
                        $pol.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection = $null

                        # Product-specific name/description
                        $rule.Name = $RuleNamePrefix + $pubInfo.ProductName
                        $rule.Description = 
                            "Product: " + $pubInfo.ProductName + "`r`n" + 
                            "Publisher: " + $pubname + "`r`n" + 
                            "File(s) found in: " + $FileSystemPaths
                    }
                }
                else
                {
                    # Anything by this publisher
                    $pol.RuleCollections.PublisherConditions.ProductName = $pol.RuleCollections.PublisherConditions.BinaryName = "*"
                    $pol.RuleCollections.PublisherConditions.BinaryVersionRange.LowSection = $null

                    # Publisher-specific name/description
                    $rule.Name = $RuleNamePrefix + $pubInfo.PublisherName
                    $rule.Description = 
                        "Publisher: " + $pubname + "`r`n" + 
                        "File(s) found in: " + $FileSystemPaths
                }

                if (!$pubPolicies.ContainsKey($key))
                {
                    # Add this publisher rule to the collection
                    #DBG "PUBLISHER RULE (" + $rtype + "): ADDING " + $key
                    $pubPolicies.Add($key, $pol)
                }
                elseif ($pubRuleInclMinver)
                {
                    # File already seen; see whether the newly-scanned file has a lower file version that needs to be allowed
                    $rulesPrev = $pubPolicies[$key]
                    foreach ( $rcPrev in $rulesPrev.RuleCollections ) { foreach($rulePrev in $rcPrev) {
                        # Get the previously-scanned file version; compare to the new one
                        $verPrev = $rulePrev.PublisherConditions.BinaryVersionRange.LowSection
                        $verCurr = $pubInfo.BinaryVersionRange.LowSection
                        if ($verCurr.CompareTo($verPrev) -lt 0)
                        {
                            # The new one is a lower file version; replace the rule we had with the new one.
                            #DBG $pubInfo.BinaryName + " REPLACE WITH EARLIER VERSION, FROM " + $verPrev.ToString() + " TO " + $verCurr.ToString()
                            $pubPolicies[$key] = $pol
                        }
                        else
                        {
                            #DBG $pubInfo.BinaryName + " KEEPING VERSION " + $verCurr.ToString() + " IN FAVOR OF " + $verPrev.ToString()
                        }
                    } }
                }
            }
            elseif ($rule -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashRule])
            {
                # If the file is signed (not by Microsoft), publisher rule granularity is publisher-only, and there's already a rule covering this file,
                # don't generate a hash rule for it.
                if ($signedFile -and !$MSSigned -and !$pubRuleInclProduct -and $pubPolicies.ContainsKey($rtype + "|" + $pubname))
                {
                    Write-Verbose -Message ("Not creating hash rule for signed file " + $alfi.Path.Path)
                }
                else
                {
                    # Hash rule - file is missing signature and/or PE version information
                    # Record the full path into the policy
                    $hashInfo = $rule.HashConditions.Hashes
                    # Key on file name and hash
                    $key = $hashInfo.SourceFileName + "|" + $hashInfo.HashDataString
                    if (!$hashPolicies.ContainsKey($key))
                    {
                        # Default rule name is just the file name; append "HASH RULE"
                        # Set the rule description to the full path.
                        # If the same file appears in multiple locations, one path will be picked; it doesn't matter which
                        $rule.Name = $RuleNamePrefix + $rule.Name + " - HASH RULE"
                        $rule.Description = "Identified in: " + $alfi.Path.Path
                        if ($signedFile)
                        {
                            $rule.Name += " for signed file"
                            $rule.Description += "`r`n" + "Signed by " + $alfi.Publisher.PublisherName + ", but missing version information"
                        }
                        # Add this hash rule to the collection
                        #DBG "HASH RULE (" + $rtype + "): ADDING " + $key
                        $hashPolicies.Add($key, $pol)
                    }
                    else
                    {
                        # Saw an identical file already
                        # "HASH RULE (" + $rtype + "): ALREADY HAVE " + $key
                    }
                }
            }
            #else
            #{
            #    "WHAT KIND OF RULE IS THIS?"
            #    $rule
            #}
        }
    }
}

####################################################################################################
# Build output
####################################################################################################

# Combine all the publisher rules into one policy and save it as XML.
if ($pubPolicies.Count -gt 0)
{
    $combinedPolicy = $null
    foreach ( $policy in $pubPolicies.Values )
    {
        if ($null -eq $combinedPolicy)
        {
            $combinedPolicy = $policy
        }
        else
        {
            $combinedPolicy.Merge($policy)
        }
    }
    SaveAppLockerPolicyAsUnicodeXml -ALPolicy $combinedPolicy -xmlFilename $OutputPubFileName
}

# Now do it for the hash rules
if ($hashPolicies.Count -gt 0)
{
    $combinedPolicy = $null
    foreach ( $policy in $hashPolicies.Values )
    {
        if ($null -eq $combinedPolicy)
        {
            $combinedPolicy = $policy
        }
        else
        {
            $combinedPolicy.Merge($policy)
        }
    }
    SaveAppLockerPolicyAsUnicodeXml -ALPolicy $combinedPolicy -xmlFilename $OutputHashFileName
}