<#
.SYNOPSIS
Builds comprehensive and robust application control "audit" and "enforce" rules for AppLocker and/or Windows Defender Application Control (WDAC) to mitigate against users running unauthorized software, \
customizable through simple text files. Writes results to the Outputs subdirectory.

TODO: Find and remove redundant rules. Report stripped rules to a separate log file.

.DESCRIPTION
Create-Policies.ps1 initializes the environment and creates shared input files used to generate comprehensive "audit" and "enforce" rules for AppLocker and/or WDAC.
The resulting policies restrict non-admin code execution to "authorized" software, in a way to minimize the need to update the rules.
Broadly speaking, "authorized" means that an administrator put it on the computer, OR created a rule specifically for that item.
* AppLocker supported operating systems include Windows 7 and newer, and Windows Server 2008 R2 and newer.
* WDAC supported operating systems include Windows 10, version 1903 and newer.
* Rules cover EXE, DLL, Script, and MSI; on Windows 8.1 and newer, rules also cover Packaged apps.
* Allows non-admin execution from the Windows and ProgramFiles directories, EXCEPT:
    * Identifies user-writable subdirectories and disallows execution from those directories;
    * Disallows execution of programs that run arbitrary code that can be used to bypass application control (e.g., mshta.exe);
    * Disallows execution of programs that non-admins rarely need but that malware/ransomware authors are known to use (e.g., cipher.exe);
* Allows execution from identified "safe" paths (non-admins cannot write to them);
* Allows execution of specifically authorized code in user-writable ("unsafe") directories.
* For WDAC, optionally allows execution of code that was placed on disk by an authorized "managed installer" such as SCCM; Managed installers currently must be configured separately
* For WDAC, optionally allows execution of code that is determined to have good reputation as determined by Microsoft's Intelligent Security Graph

Rule implementation:
Rule types cover path rules, publisher/signature rules, and hash rules.
Rules allowing execution from "safe" locations are implemented using path rules.
For AppLocker, user-writable subdirectories of the Windows and ProgramFiles directories are identified using Sysinternals AccessChk.exe. Exceptions for those subdirectories are implemented within path rules.
WDAC user-writable checks are performed at runtime and skips the scan using Sysinternals AccessChk.exe unless KnownAdmins.ps1 finds custom admins defined
Exceptions for "dangerous" programs (e.g., mshta.exe, cipher.exe) are generally implemented with publisher/signature rules.
Rules allowing execution of EXE, DLL, and script files from user-writable directories are implemented with publisher/signature rules when possible, and hash rules otherwise, with options for the granularity of Publisher/signature rules.
Publisher/signature rules can also be created allowing execution of anything signed by a particular publisher, or a specific product by a particular publisher.

Scanning for user-writable subdirectories of the Windows and ProgramFiles directories can be time-consuming and is only required for AppLocker or when custom admins are defined. 
The script writes results to text files in an intermediate subdirectory. The script runs the scan if those files are not found OR if the -Rescan switch is specified.
It is STRONGLY recommended that the scanning be performed with administrative rights.
Once scans have been performed, scanned output can be copied to another machine and rules can be maintained without needing to rescan.

Dependencies:
PowerShell v5.1 or higher (Windows Management Framework 5.1 or higher)
Current (or recent) version of Sysinternals AccessChk.exe, either in the Path or in the same directory as this script.
Scripts and support files included in this solution (some are in specific subdirectories).

See external documentation for more information.

.LINK
Sysinternals AccessChk is available here:
    https://technet.microsoft.com/sysinternals/accesschk
    https://download.sysinternals.com/files/AccessChk.zip
    https://live.sysinternals.com/accesschk.exe
or run .\Support\DownloadAccesschk.ps1, which downloads AccessChk.exe to the main AaronLocker directory.

.PARAMETER Rescan
If this switch is set, this script scans the Windows and ProgramFiles directories for user-writable subdirectories, and captures data about EXE files to blacklist.
If the results from a previous scan are found in the expected location and this switch is not specified, the script does not perform those scans. If those results are not found, the script performs the scan even if this switch is not set.
It is STRONGLY recommended that the scanning be performed with administrative rights.

.PARAMETER ForUser
If scanning a system with an administrative account with a need to inspect another user's profile for "unsafe paths," specify that username with this optional parameter. E.g., if logged on and scanning with administrative account "abby-adm" but need to inspect $env:USERPROFILE belonging to "toby", use -ForUser toby.

.PARAMETER Excel
If specified, also creates Excel spreadsheets representing the generated rules.

.PARAMETER AppLockerOrWDAC
Specifies whether to generate policy for WDAC, AppLocker, or Both (default).
#>



####################################################################################################
# Parameters
####################################################################################################

param(
	# If set, forces rescans for user-writable directories under Windows and ProgramFiles
	[switch]
	$Rescan = $false,

    # If set, replaces current user name with another in "unsafe paths"
    [parameter(Mandatory=$false)]
    [String]
    $ForUser,

    # If specified, also creates Excel spreadsheets representing the generated rules.
    [switch]
    $Excel,
    
    # Specifies whether to create policies for WDAC only, AppLocker only, or Both (default)
    [ValidateSet("Both","AppLocker","WDAC")]
    [String]
    $AppLockerOrWDAC = "Both"
)

####################################################################################################
# Initialize
####################################################################################################

# --------------------------------------------------------------------------------
# Only supported PowerShell version at this time: 5.1
# PS Core v6.x doesn't include AppLocker cmdlets; string .Split() has new overloads that need to be dealt with.
# (At some point, may also need to check $PSVersionTable.PSEdition)
$psv = $PSVersionTable.PSVersion
if ($psv.Major -ne 5 -or $psv.Minor -ne 1)
{
    $errMsg = "This script requires PowerShell v5.1.`nCurrent version = " + $PSVersionTable.PSVersion.ToString()
    Write-Error $errMsg
    return
}

# Make sure this script is running in FullLanguage mode
if ($ExecutionContext.SessionState.LanguageMode -ne [System.Management.Automation.PSLanguageMode]::FullLanguage)
{
    $errMsg = "This script must run in FullLanguage mode, but is running in " + $ExecutionContext.SessionState.LanguageMode.ToString()
    Write-Error $errMsg
    return
}

# --------------------------------------------------------------------------------
# If WDAC or Both, make sure the OS is Windows 10 version 1903 (build 18362) or greater
$OSBuild = [System.Environment]::OSVersion.Version.Build
if ( ($AppLockerOrWDAC -eq "WDAC") -and ($OSBuild -lt 18362) )
{
    $errMsg = ("AaronLocker supports WDAC on Windows 10 version 1903 (build 18362) and greater. Current build is " + $OSBuild + ".")
    Write-Error $errMsg
    return
}
elseif ( ($AppLockerOrWDAC -eq "Both") -and ($OSBuild -lt 18362) )
{
    Write-Host ("AaronLocker supports WDAC on Windows 10 version 1903 (build 18362) and greater. Current build is " + $OSBuild + ". Processing AppLocker only.") -ForegroundColor Cyan
    $AppLockerOrWDAC = "AppLocker"
}
# --------------------------------------------------------------------------------

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file.
. $rootDir\Support\Config.ps1

# Create subdirectories if they don't exist (some have to exist because files are expected to be there).
if (!(Test-Path($customizationInputsDir))) { mkdir $customizationInputsDir | Out-Null }
if (!(Test-Path($mergeRulesDynamicDir)))   { mkdir $mergeRulesDynamicDir | Out-Null }
if (!(Test-Path($mergeRulesStaticDir)))    { mkdir $mergeRulesStaticDir | Out-Null }
if (!(Test-Path($outputsDir)))             { mkdir $outputsDir | Out-Null }
if (!(Test-Path($supportDir)))             { mkdir $supportDir | Out-Null }
if (!(Test-Path($scanResultsDir)))         { mkdir $scanResultsDir | Out-Null }

# Look for results from previous scan for user-writable directories under the Windows and ProgramFiles directories.
# If any of the files containing the filtered results are missing, force a rescan.
if ( ! ( (Test-Path($windirTxt)) -and (Test-Path($PfTxt)) -and (Test-Path($Pf86Txt)) ) )
{
    $Rescan = $true
}

# Get custom admins, if any defined
[System.Collections.ArrayList]$knownAdmins = @()
$knownAdmins.AddRange( @(& $ps1_KnownAdmins) )

# If one or more custom admins was found, override WDAC's runtime admin-writable-only check and instead revert to AppLocker parity
if ($knownAdmins.Count -gt 0) {$ProcessWDACLikeAppLocker = $true}
else {$ProcessWDACLikeAppLocker = $false}

# If just processing WDAC and no custom admins are defined, 
if (($Rescan) -and ($AppLockerOrWDAC -eq "WDAC") -and !($ProcessWDACLikeAppLocker))
{
    Write-Host "Skipping scan for user-writable directories - not required for WDAC unless one or more custom admins exist" -ForegroundColor Cyan
    $Rescan = $false
}

####################################################################################################
# Scan Windir and ProgramFiles directories if needed
####################################################################################################

# --------------------------------------------------------------------------------
# If $Rescan enabled, enumerate user-writable directories under %windir% and the ProgramFiles directories
# (scans the '(x86)' one only if present; doesn't raise an error if not present).
# This must be done at least once. Note that it can be time-consuming. Admin rights are recommended.
# Scanning requires that Sysinternals AccessChk.exe be in the Path or in the script directory. If it isn't,
# this script writes an error message and quits.
# Outputs the list of all writable subdirectories to "*_Full.txt"; the rules are built using those results with redundant lines removed.
# The filtered lists can be hand-edited if absolutely necessary.
if ($Rescan)
{
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
    # Otherwise, if AccessChk.exe not available in the path, write an error message and quit.
    elseif ($null -eq (Get-Command AccessChk.exe -ErrorAction SilentlyContinue))
    {
        $errMsg = "Scanning for writable subdirectories requires that Sysinternals AccessChk.exe be in the Path or in the same directory with this script.`n" +
            "AccessChk.exe was not found.`n" +
            "(See .\Support\DownloadAccesschk.ps1 for help.)`n" +
            "Exiting..."
        Write-Error $errMsg
        return
    }

    # Enumerate user-writable subdirectories in protected directories. Capture grantees so they can be inspected afterwards.
	Write-Host "Enumerating writable directories in $env:windir" -ForegroundColor Cyan
	& $ps1_EnumWritableDirs -RootDirectory $env:windir -ShowGrantees -OutputXML -KnownAdmins $knownAdmins | Out-File -Encoding ASCII $windirFullXml
	Write-Host "Enumerating writable directories in $env:ProgramFiles" -ForegroundColor Cyan
	& $ps1_EnumWritableDirs -RootDirectory $env:ProgramFiles -ShowGrantees -OutputXML -KnownAdmins $knownAdmins | Out-File -Encoding ASCII $PfFullXml
    # The following applies only to 64-bit Windows; skip it on 32-bit and create an empty file
    if ($null -ne ${env:ProgramFiles(x86)})
    {
	    Write-Host "Enumerating writable directories in ${env:ProgramFiles(x86)}" -ForegroundColor Cyan
	    & $ps1_EnumWritableDirs -RootDirectory ${env:ProgramFiles(x86)} -ShowGrantees -OutputXML -KnownAdmins $knownAdmins | Out-File -Encoding ASCII $Pf86FullXml
    }
    else
    {
        # Create an empty file so the rest of the script doesn't have to take 32/64 into account.
        New-Item $Pf86FullXml -ItemType File | Out-Null
    }
    # Restore original Path if it was altered for AccessChk.exe
    if ($origPath.Length -gt 0)
    {
        $env:Path = $origPath
    }

    # If a directory grants these permissions, the grantee can write an alternate data stream to the directory
    # and execute it
    $ADSWriteAndExecPerms =
        [System.Security.AccessControl.FileSystemRights]::CreateFiles +
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories +
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes +
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes +
        [System.Security.AccessControl.FileSystemRights]::ReadData +
        [System.Security.AccessControl.FileSystemRights]::ExecuteFile
    $InheritOnly =
        [System.Security.AccessControl.PropagationFlags]::InheritOnly;

    # Function to determine whether a non-admin can create/modify an alternate data stream (ADS) on the directory
    function HasWritableADS([System.Xml.XmlElement] $dirItem)
    {
        # Write-Verbose ($dirItem.name + ", " + $dirItem.Grantee)
        $totalRights = [System.Security.AccessControl.FileSystemRights]0;
        $acl = Get-Acl -LiteralPath $dirItem.Name
        foreach( $grantee in $dirItem.Grantee ) 
        {
            # Write-Verbose $grantee
            foreach ( $ace in $acl.Access )
            {
                # Write-Verbose ($ace.FileSystemRights.ToString() + " | " + $ace.PropagationFlags.ToString())
                # ACE applies to identified non-admin entity and isn't marked InheritOnly
                if (($ace.IdentityReference.Value -eq $grantee) -and (($ace.PropagationFlags -band $InheritOnly) -eq 0))
                {
                    # Sum them up
                    $totalRights = $totalRights -bor $ace.FileSystemRights
                }
            }
        }
        # Write-Verbose "totalRights = $totalRights"
        return (($totalRights -band $ADSWriteAndExecPerms) -eq $ADSWriteAndExecPerms)
    }

    # Function to remove redundancies from lists of user-writable directories enumerated in the supplied XML.
    # Assumes that input is an XML listing user-writable directories. This script sorts the list of directory names alphabetically, 
    # and then removes any entries for which a parent directory has already been identified.
    # WHILE WE'RE AT IT, when we identify the top-parent writable directories, determine whether the directory allows a non-admin
    # to add an Alternate Data Stream. If so, output a line to exclude execution from any ADS on the directory.
    function RemoveRedundantLinesAndIdentifyWritableADS([String] $fnameFullXml)
    {
        $x = [xml](Get-Content $fnameFullXml)
        if ($null -ne $x)
        {
            $lastItem = ""
            # Case-insensitive alphabetic sort of directory names
            $x.root.dir | Sort-Object name | foreach {
                # First item in sorted list will be output.
                # Anything that was output becomes $lastItem, lower-cased and ending with backslash.
                # Anything that follows that matches $lastItem's full length (with backslash) must be a subdirectory -
                # do not output that.
                # When something doesn't match, it must be something other than a subdirectory of previous $lastItem.
                # Write it out and make it $lastItem, lower-cased and ending with backslash.
                $thisItem = $_
                if ($lastItem.Length -eq 0 -or !$thisItem.name.ToLower().StartsWith($lastItem))
                {
                    # Write output that serves as an exclusion for everything in this directory (including subdirectories)
                    Write-Output ($thisItem.name + "\*")
                    if (HasWritableADS($thisItem))
                    {
                        # Write output that serves as an exclusion for any potential ADSes of this directory
                        Write-Output ($thisItem.name + ":*")
                        #Write-Verbose ("Writable ADS: " + $thisItem.name)
                        #Write-Verbose ("----------------------------")
                    }
                    $lastItem = $thisItem.name.ToLower()
                    if (!$lastItem.EndsWith("\")) { $lastItem += "\" }
                }
            }
        }
    }

    Write-Host "Removing redundancies in scan results" -ForegroundColor Cyan
    RemoveRedundantLinesAndIdentifyWritableADS $windirFullXml | Out-File -Encoding ASCII $windirTxt
    RemoveRedundantLinesAndIdentifyWritableADS $PfFullXml     | Out-File -Encoding ASCII $PfTxt
    RemoveRedundantLinesAndIdentifyWritableADS $Pf86FullXml   | Out-File -Encoding ASCII $Pf86Txt
}

####################################################################################################
# Process common custom inputs once before calling AppLocker- and WDAC-specific scripts
####################################################################################################
# Get Block List -- WDAC could potentially use recommended blocks policy instead? If so, move this back to AppLocker-specific script
if ( $Rescan -or ( ($AppLockerOrWDAC -in "Both","AppLocker") -and !(Test-Path($ExeBlacklistData) ) ) -or ( ($AppLockerOrWDAC -in "Both","WDAC") -and !(Test-Path($WDACBlockPolicyXML) ) ) )
{
    Write-Host "Get EXE files to blacklist for later processing..." -ForegroundColor Cyan
    # Get the EXE files to blacklist from the script that produces that list.
    $exeFilesToBlacklist = (& $ps1_GetExeFilesToBlacklist)
}

# Get additional authorized safe paths from the script that produces that list 
Write-Host "Get authorized safe paths for later processing..." -ForegroundColor Cyan
$PathsToAllow = (& $ps1_GetSafePathsToAllow)
$PathsToAllow | foreach {
    # If path is an existing directory and doesn't have trailing "\*" appended, fix it so that it does.
    # If path is a file, don't append \*. If the path ends with \*, no need for further validation.
    # If it doesn't end with \* but Get-Item can't identify it as a file or a directory, write a warning and accept it as is.
    $pathToAllow = $_
    if (!$pathToAllow.EndsWith("\*"))
    {
        $pathItem = Get-Item $pathToAllow -Force -ErrorAction SilentlyContinue
        if ($pathItem -eq $null)
        {
            Write-Warning "Cannot verify path $pathItem; adding to rule set as is."
        }
        elseif ($pathItem -is [System.IO.DirectoryInfo])
        {
            Write-Warning "Appending `"\*`" to rule for $pathToAllow"
            $pathToAllow = [System.IO.Path]::Combine($pathToAllow, "*")
        }
    }
}


####################################################################################################
# Shared setup complete. Call AppLocker- and WDAC-specific scripts.
####################################################################################################
if ($AppLockerOrWDAC -in "Both","AppLocker") {& $ps1_CreatePoliciesAppLocker}
if ($AppLockerOrWDAC -in "Both","WDAC")      {& $ps1_CreatePoliciesWDAC}

# --------------------------------------------------------------------------------