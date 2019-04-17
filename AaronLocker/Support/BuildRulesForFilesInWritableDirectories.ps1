<#
.SYNOPSIS
Builds tightly-scoped but forward-compatible AppLocker rules for files in user-writable directories. The rules are intended to be merged into a larger set using Create-Policies.ps1 in the root directory.

.DESCRIPTION
This script takes a list of one or more file system objects (files and/or directories) and generates rules to allow execution of the corresponding files.

Rule files generated with this script can be incorporated into comprehensive rule sets using Create-Policies.ps1 in the root directory.

Publisher rules are generated where possible:
* Publisher rules restrict to a specific binary name, product name, and publisher, and (optionally) the identified version or above.
* Redundant rules are removed; if multiple versions of a specific file are found, the rule allows execution of the lowest-identified version or above.
Hash rules are generated when publisher rules cannot be created.
The script creates rule names and descriptions designed for readability in the Security Policy editor. The RuleNamePrefix option enables you to give each rule in the set a common prefix (e.g., "OneDrive") to make the source of the rule more apparent and so that related rules can be grouped alphabetically by name.
The rules' EnforcementMode is left NotConfigured. (Create-Policies.ps1 takes care of setting EnforcementMode in the larger set.)
(Note that the New-AppLockerPolicy's -Optimize switch "overoptimizes," allowing any file name within a given publisher and product name. Not using that.)

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

.PARAMETER EnforceMinimumVersion
If this switch is specified, generated publisher rules enforce minimum file version based on versions of the scanned files; otherwise rules do not enforce file versions

.PARAMETER OutputFileName
Required: the name/path of the XML output file containing the generated rules.

.PARAMETER RuleNamePrefix
Optional: If specified, all rule names begin with the specified RuleNamePrefix.

.EXAMPLE
.\BuildRulesForFilesInWritableDirectories.ps1 -FileSystemPaths $env:LOCALAPPDATA\Microsoft\OneDrive -RecurseDirectories -RuleNamePrefix OneDrive -OutputFileName ..\WorkingFiles\OneDriveRules.xml

Scans the OneDrive directory and subdirectories in the current user's profile.
All generated rule names will begin with "OneDrive".
The generated rules are written to ..\WorkingFiles\OneDriveRules.xml.

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

    # If specified, publisher rules enforce minimum file versions; otherwise, generated publisher rules do not restrict based on file version.
    [switch]
    $EnforceMinimumVersion,

    # Optional prefix incorporated into each rule name
    [parameter(Mandatory=$false)]
    [String]
    $CustomUserOrGroupSid,

    # Name of output file
    [parameter(Mandatory=$true)]
    [String]
    $OutputFileName,

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

# Build an absolute path for the output file name
if (![System.IO.Path]::IsPathRooted($OutputFileName))
{
    $rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    $OutputFileName = [System.IO.Path]::Combine($rootDir, $OutputFileName)
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

# Array of AppLocker File Information objects
$arrALFI = @()
# Hash table of rules with redundant entries removed
$policies = @{}

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
                [array]$scanFileTypes = @('*.bat','*.com','*.exe','*.dll','*.ocx','*.js','*.ps1','*.pyd','*.vbs','*.xll')

                if ($RecurseDirectories)
                {
                    $files += Get-ChildItem * -Path $fsp -File -Force -Recurse -Include $scanFileTypes
                    for ($i = 0; $i -lt $files.Count; $i++)
                    {   
                        $arrALFI += Get-AppLockerFileInformation -Path $files[$i].FullName
                    }
                }
                else
                {
                    $files += Get-ChildItem * -Path $fsp -File -Force -Include $scanFileTypes
                    for ($i = 0; $i -lt $files.Count; $i++)
                    {   
                        $arrALFI += Get-AppLockerFileInformation -Path $files[$i].FullName
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
    # Favor publisher rule; hash rule otherwise
    $pol = New-AppLockerPolicy -FileInformation $alfi -RuleType Publisher,Hash -User $CustomUserOrGroupSid

    foreach ($ruleCollection in $pol.RuleCollections)
    {
        $rtype = $ruleCollection.RuleCollectionType
        foreach($rule in $ruleCollection)
        {
            # Publisher rule - file is signed and has required PE version information
            if ($rule -is [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule])
            {
                $pubInfo = $rule.PublisherConditions
                # Key on file name, product name, and publisher name; don't incorporate version number into the key
                $key = $pubInfo.BinaryName + "|" + $pubInfo.ProductName + "|" + $pubInfo.PublisherName
                # Build new rule name and description
                $rule.Description = "Product: " + $pubInfo.ProductName + "`r`n" + "Publisher: " + $pubInfo.PublisherName + "`r`n" + "Original path: " + $alfi.Path.Path
                $rule.Name = $RuleNamePrefix + $pubInfo.BinaryName
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
                if (!$policies.ContainsKey($key))
                {
                    # Add this publisher rule to the collection
                    #DBG "PUBLISHER RULE (" + $rtype + "): ADDING " + $key
                    $policies.Add($key, $pol)
                }
                elseif ($EnforceMinimumVersion)
                {
                    # File already seen; see whether the newly-scanned file has a lower file version that needs to be allowed
                    $rulesPrev = $policies[$key]
                    foreach ( $rcPrev in $rulesPrev.RuleCollections ) { foreach($rulePrev in $rcPrev) {
                        # Get the previously-scanned file version; compare to the new one
                        $verPrev = $rulePrev.PublisherConditions.BinaryVersionRange.LowSection
                        $verCurr = $pubInfo.BinaryVersionRange.LowSection
                        if ($verCurr.CompareTo($verPrev) -lt 0)
                        {
                            # The new one is a lower file version; replace the rule we had with the new one.
                            #DBG $pubInfo.BinaryName + " REPLACE WITH EARLIER VERSION, FROM " + $verPrev.ToString() + " TO " + $verCurr.ToString()
                            $policies[$key] = $pol
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
                # Hash rule - file is missing signature and/or PE version information
                # Record the full path into the policy
                $hashInfo = $rule.HashConditions.Hashes
                # Key on file name and hash
                $key = $hashInfo.SourceFileName + "|" + $hashInfo.HashDataString
                if (!$policies.ContainsKey($key))
                {
                    # Default rule name is just the file name; append "HASH RULE"
                    # Set the rule description to the full path.
                    # If the same file appears in multiple locations, one path will be picked; it doesn't matter which
                    $rule.Name = $RuleNamePrefix + $rule.Name + " - HASH RULE"
                    $rule.Description = "Identified in: " + $alfi.Path.Path
                    # Add this hash rule to the collection
                    #DBG "HASH RULE (" + $rtype + "): ADDING " + $key
                    $policies.Add($key, $pol)
                }
                else
                {
                    # Saw an identical file already
                    # "HASH RULE (" + $rtype + "): ALREADY HAVE " + $key
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

# Combine all the rules into one policy and save it as XML.
$combinedPolicy = $null
foreach ( $policy in $policies.Values )
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
SaveAppLockerPolicyAsUnicodeXml -ALPolicy $combinedPolicy -xmlFilename $OutputFileName

