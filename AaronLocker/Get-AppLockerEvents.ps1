<#
.SYNOPSIS
Retrieves and sorts event data from AppLocker logs, synthesizes data, and reports as tab-delimited CSV output, PSCustomObjects, or as an Excel worksheet.

.DESCRIPTION
Get-AppLockerEvents.ps1 retrieves AppLocker event data from live or saved event logs on the local or a remote computer in a manner that makes analysis much easier than the raw data itself.
In addition to reporting the raw data from the logs, Get-AppLockerEvents.ps1 synthesizes data so that commonalities between events involving different users or computers can be aggregated.
Output can be tab-delimited CSV (the default), an array of PSCustomObjects, or a formatted Excel worksheet.

By default, the script retrieves error and warning events from the AppLocker EXE/DLL, MSI/Script, and Packaged app-Execution event logs on the local computer.
You can specify a remote computer, omit one or two of the default logs. AppLocker in audit mode produces warning events ("would have been blocked"), while enforce mode produces error events ("was blocked").
You can choose to report only errors, only warnings, only allowed (information) events, or all events.

For forwarded events, you can retrieve from the ForwardedEvents log, and/or named event logs if you've forwarded AppLocker events to log(s) other than to ForwardedEvents.
Instead of live logs, you can specify the paths to one or more exported .evtx event log files.

The -FromDateTime and -ToDateTime options enable you to limit events to time ranges.

Data from each event is turned into a line of tab-delimited CSV. Lines are sorted before being output.

Random-named temporary files created by PowerShell to test whitelisting policy are filtered out by default.

Use the -ComputerName parameter to name a remote computer from which to retrieve live-log events (default logs or event collectors).
Use the -WarningOnly, -ErrorOnly, -AllowedOnly, or -AllEvents switches to retrieve events other than errors and warnings.
Use the -NoExeAndDll, -NoMsiAndScript, and -NoPackagedAppExec switches not to retrieve events from one or two default AppLocker logs.
Use the -ForwardedEvents switch to read from the ForwardedEvents log instead of from the default AppLocker logs.
Use -EventLogNames to specify the names of logs where AppLocker events were forwarded.
Use the -EvtxLogFilePaths parameter to name one or more saved event log files to read.
Use the -FromDateTime and -ToDateTime parameters to restrict the date/time range to report.
Use the -NoPsFilter switch not to filter out random-named PowerShell policy test script files.

See the detailed parameter descriptions for more information.

Output fields:

* Location      high-level indicator of file location, such as "User profile," "Hot/removable," "ProgramData," etc.
* GenericPath   is the original file path with "%LOCALAPPDATA%" replacing the beginning of the path name
                if it matches the typical pattern "C:\Users\[username]\AppData\Local".
                Makes similar replacements for "%APPDATA%" or "%USERPROFILE%" if LOCALAPPDATA isn't applicable.
* GenericDir    is the directory-name portion of GenericPath (i.e., with the filename removed).
* OriginalPath  is the file path exactly as reported in the AppLocker event log data.
                If a file is used by multiple users, OriginalPath often includes differentiating information such as user profile name.
* FileName      is the logged filename (including extension) by itself without path information.
* FileExt       is the file extension of the logged file. This can be useful to track files with non-standard file extensions. (Always left empty for packaged apps.)
* FileType      is EXE, DLL, MSI, SCRIPT, or APPX.
* PublisherName for signed files is the distinguished name (DN) of the file's digital signer. PublisherName is blank or just a hyphen if the file is not signed by a trusted publisher.
* ProductName   for signed files is the product name taken from the file's version resource.
* BinaryName    for signed files is the "OriginalName" field taken from the file's version resource.
* FileVersion   for signed files is the binary file version taken from the file's version resource.
* Hash          represents the file's SHA256 hash. In addition to being incorporated in rule data, the hash data can help determine whether two files are identical.
* UserSID       is the security identifier (SID) of the user that ran or tried to run the file.
* UserName      is the result of SID-to-name translation of the UserSID value performed on the local computer.
* MachineName   is the computer name on which the event was logged.
* EventTime     is the date and time that the event occurred, in the computer's local time zone and rendered in this sortable format "yyyy-MM-ddTHH:mm:ss.fffffff".
                For example, June 13, 2018, 6:49pm plus 17.7210233 seconds is reported as 2018-06-13T18:49:17.7210233.
* EventTimeXL   is the date and time that the event occurred, in the computer's local time zone and rendered in a format that Excel recognizes as a date/time, and its filter dropdown renders in a tree view.
* PID           is the process ID. It can be used to correlate EXE files and other file types, including scripts and DLLs.
                Note that a PID is a unique identifier only on the computer the process is running on and only while it is running. When the process exits, the PID value can be assigned to another process.
* EventType     is "Information," "Warning," or "Error," which can be particularly helpful with -AllEvents, as it's not otherwise possible to tell whether the file was allowed.

.PARAMETER ComputerName
Retrieves event data from live event logs on the named remote computer instead of the local computer. Caller must have administrative rights on the remote computer.
(Can be used in DefaultAppLockerLogs or LiveWEFLogs mode, but not in SavedLogs mode.)

.PARAMETER NoExeAndDll
When specified in DefaultAppLockerLogs mode, does not retrieve events from the AppLocker EXE and DLL log.

.PARAMETER NoMsiAndScript
When specified in DefaultAppLockerLogs mode, does not retrieve events from the AppLocker MSI and Script log.

.PARAMETER NoPackagedAppExec
When specified in DefaultAppLockerLogs mode, does not retrieve events from the AppLocker Packaged app-Execution log.

.PARAMETER ForwardedEvents
Retrieves events from the ForwardedEvents log instead of from the default AppLocker logs. Can also be used with -EventLogNames.

.PARAMETER EventLogNames
Retrieves events from the named live event logs. (Intended for use with Windows Event Collectors.) Can also be used with -ForwardedEvents.

.PARAMETER EvtxLogFilePaths
Specifies path to one or more saved .evtx event log files.

.PARAMETER WarningOnly
Reports only Warning events (AuditOnly mode; "would have been blocked"), instead of Errors + Warnings.

.PARAMETER ErrorOnly
Reports only Error events (Enforce mode; files actually blocked), instead of Errors + Warnings.

.PARAMETER AllowedOnly
Reports only Information events (files allowed to run) instead of Errors + Warnings.

.PARAMETER AllEvents
Reports all Information, Warning, and Error events.

.PARAMETER FromDateTime
Reports only events on or after the specified date or date-time. E.g., -FromDateTime "9/7/2017" or -FromDateTime "9/7/2017 12:00:00"
Can be used with -ToDateTime to specify a date/time range. Date/time specified in local time zone.

.PARAMETER ToDateTime
Reports only events on or before the specified date or date-time. E.g., -ToDateTime "9/7/2017" or -ToDateTime "9/7/2017 12:00:00"
Can be used with -FromDateTime to specify a date/time range. Date/time specified in local time zone.

.PARAMETER NoAutoNGEN
If specified, does not report modern-app AutoNGEN files that are unsigned and in the user's profile.

.PARAMETER NoPSFilter
If specified, does not try to filter out random-named PowerShell scripts used to determine whether whitelisting is in effect.

.PARAMETER NoFilteredMachines
By default, this script outputs a single artificial "empty" event line for every machine for which all observed events were filtered out.

.PARAMETER Excel
If this optional switch is specified, outputs to a formatted Excel rather than tab-delimited CSV text to the pipeline.

.PARAMETER Objects
If this optional switch is specified, outputs PSCustomObjects rather than tab-delimited CSV. (Passes CSV through ConvertFrom-Csv.)
This switch is ignored if -Excel is also specified.


.EXAMPLE
.\Get-AppLockerEvents.ps1 -NoMsiAndScript -NoPackagedAppExec

Retrieves warning and error events from the AppLocker EXE and DLL log (MSI/Script and PackagedApp omitted).

.EXAMPLE
.\Get-AppLockerEvents.ps1 -Computer CONTOSO\RECEPTION1 -AllEvents -FromDateTime "6/1/2019 8:00" -ToDateTime "6/1/2019 9:00" -Excel

Retrieves all AppLocker events for a specified one-hour period on CONTOSO\RECEPTION1, and report in an Excel document.

.EXAMPLE
.\Get-AppLockerEvents.ps1 -EvtxLogFilePaths .\ForwardedEvents1.evtx, .\ForwardedEvents2.evtx

Get warning and error events from events exported into ForwardedEvents1.evtx and ForwardedEvents2.evtx.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -Objects | Where-Object { $_.PublisherName -eq "[not signed]" }

Get warning and error events from the default AppLocker logs where target file is unsigned. Results are output to the PowerShell pipeline as PSCustomObjects.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -AllowedOnly -Objects | Group-Object PublisherName

Get allowed files from EXE/DLL, MSI/Script, and PackagedApp logs on the local computer. Convert output into objects, group the objects according to the PublisherName field.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -Objects | Where-Object { $_.PublisherName.Contains("CONTOSO") } | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation

Get warning and error events from the default AppLocker logs on the local computer involving files signed by Contoso, converting back into tab-delimited CSV.

.EXAMPLE
$ev = .\Get-AppLockerEvents.ps1 -Objects
$ev | Select-Object UserName, MachineName -Unique | Sort-Object UserName, MachineName
$ev.FileExt | Sort-Object -Unique

Output a list of each combination of users and machines reporting events, and a list of all observed file extensions involved with events.

#>

[CmdletBinding(DefaultParameterSetName="DefaultAppLockerLogs")]
param(
    # Optional remote computer name with default AppLocker logs or other live logs
    [parameter(ParameterSetName="DefaultAppLockerLogs", Mandatory=$false)]
    [parameter(ParameterSetName="LiveWEFLogs", Mandatory=$false)]
    [String]
    $ComputerName,

    # When using default AppLocker logs, can exclude one or two of them.
    [parameter(ParameterSetName="DefaultAppLockerLogs")]
    [switch]
    $NoExeAndDll = $false,
    [parameter(ParameterSetName="DefaultAppLockerLogs")]
    [switch]
    $NoMsiAndScript = $false,
    [parameter(ParameterSetName="DefaultAppLockerLogs")]
    [switch]
    $NoPackagedAppExec = $false,

    # Instead of default AppLocker logs, can use ForwardedEvents and/or any named logs
    [parameter(ParameterSetName="LiveWEFLogs")]
    [switch]
    $ForwardedEvents = $false,
    [parameter(ParameterSetName="LiveWEFLogs", Mandatory=$false)]
    [String[]]
    $EventLogNames,

    # Can use saved event logs instead of live event logs
    [parameter(ParameterSetName="SavedLogs", Mandatory=$false)]
    [String[]]
    $EvtxLogFilePaths,

    # Which event types to inspect (default is Warnings + Errors)
    [switch]
    $WarningOnly = $false,
    [switch]
    $ErrorOnly = $false,
	[switch]
	$AllowedOnly = $false,
    [switch]
    $AllEvents = $false,

    # Optional date range
    [parameter(Mandatory=$false)]
    [datetime]
    $FromDateTime,
    [parameter(Mandatory=$false)]
    [datetime]
    $ToDateTime,

    # If specified, does not report modern-app AutoNGEN files that are unsigned and in the user's profile.
    [switch]
    $NoAutoNGEN = $false,

    # This script filters out PowerShell policy test scripts by default. The -NoPSFilter switch allows those not to be filtered.
    [switch]
    $NoPSFilter = $false,

    # If specified, do not create artificial "empty" event lines for machines for which all observed events were filtered out.
    [switch]
    $NoFilteredMachines = $false,

    # Output to Excel
    [switch]
    $Excel,

    # Output PSCustomObjects
    [switch]
    $Objects
)

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
$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file.
. $rootDir\Support\Config.ps1

#
# Strings/IDs
#
$ExeDllLogName    = 'Microsoft-Windows-AppLocker/EXE and DLL'
$MsiScriptLogName = 'Microsoft-Windows-AppLocker/MSI and Script'
$PkgdAppExecLogName='Microsoft-Windows-AppLocker/Packaged app-Execution'
$FwdEventsLogName = 'ForwardedEvents'
$ExeDllAllowed    = 'EventID=8002'
$ExeDllWarning    = 'EventID=8003'
$ExeDllError      = 'EventID=8004'
$MsiScriptAllowed = 'EventID=8005'
$MsiScriptWarning = 'EventID=8006'
$MsiScriptError   = 'EventID=8007'
$PkgdAppAllowed   = 'EventID=8020'
$PkgdAppWarning   = 'EventID=8021'
$PkgdAppError     = 'EventID=8022'
$SubscriptionBkmrk= 'EventID=111'
$WecBkmarkEventID = 111
$AppxEventIDs     = (8020, 8021, 8022)

#
# Event logs to query
#
[System.Collections.ArrayList]$eventLogs = @()

# Not filtering on event provider if we don't have to... (maybe should... Saved WEF log might have events besides AppLocker and EventForwarder... Maybe should just always have it? Perf?)
$eventProviderFilter = ""

Write-Verbose ("ParameterSetName = " + $PSCmdlet.ParameterSetName)
switch($PSCmdlet.ParameterSetName)
{
    "DefaultAppLockerLogs"
    {
        if (!$NoExeAndDll)       { $eventLogs.Add($ExeDllLogName) | Out-Null }
        if (!$NoMsiAndScript)    { $eventLogs.Add($MsiScriptLogName) | Out-Null }
        if (!$NoPackagedAppExec) { $eventLogs.Add($PkgdAppExecLogName) | Out-Null }
    }
    
    "LiveWEFLogs"
    {
        # Set XPath to filter on provider so we don't inadvertently get events from sources we don't know about.
        $eventProviderFilter = "Provider[@Name='Microsoft-Windows-AppLocker' or @Name='Microsoft-Windows-EventForwarder'] and"

        if ($ForwardedEvents)
        {
            $eventLogs.Add($FwdEventsLogName) | Out-Null
        }

        if ($EventLogNames)
        {
            # Named log(s) - to support case where Windows Event Collector collects events in one or more logs other than ForwardedEvents
            $eventLogs.AddRange($EventLogNames)
        }
    }
}

if ($eventLogs.Count -eq 0 -and $EvtxLogFilePaths.Length -eq 0)
{
    Write-Error "No logs to inspect."
    return
}

#
# Eventlog XPath query: optional date/time filtering
#
$dateTimeFilter = ""
if ($FromDateTime -or $ToDateTime)
{
    if ($FromDateTime)
    {
        $dateTimeFilter = "TimeCreated[@SystemTime>='" + $FromDateTime.ToUniversalTime().ToString("s") + "']"
        if ($ToDateTime)
        {
            $dateTimeFilter += " and "
        }
    }
    if ($ToDateTime)
    {
        $dateTimeFilter += "TimeCreated[@SystemTime<='" + $ToDateTime.ToUniversalTime().ToString("s") + "']"
    }

    $dateTimeFilter = "($dateTimeFilter) and"
}

#
# Event log XPath query: event IDs
#
$eventIdFilter = "$ExeDllWarning or $MsiScriptWarning or $PkgdAppWarning or $ExeDllError or $MsiScriptError or $PkgdAppError"
if ($WarningOnly)
{
    $eventIdFilter = "$ExeDllWarning or $MsiScriptWarning or $PkgdAppWarning"
}
if ($ErrorOnly)
{
    $eventIdFilter = "$ExeDllError or $MsiScriptError or $PkgdAppError"
}
if ($AllowedOnly)
{
    $eventIdFilter = "$ExeDllAllowed or $MsiScriptAllowed or $PkgdAppAllowed"
}
if ($AllEvents)
{
    $eventIdFilter = "$ExeDllAllowed or $MsiScriptAllowed or $PkgdAppAllowed or $ExeDllWarning or $MsiScriptWarning or $PkgdAppWarning or $ExeDllError or $MsiScriptError or $PkgdAppError"
}
if (($ForwardedEvents -or $EventLogNames -or $EvtxLogFilePaths) -and !$NoFilteredMachines)
{
    # If forwarded events, also pick up subscription bookmark events. (Assume that $EventLogNames implies event collector, and that $EvtxLogFilePaths might.)
    $eventIdFilter += " or $SubscriptionBkmrk"
}
$eventIdFilter = "($eventIdFilter)"

#
# Set the XPath filter for the event log(s) query
#
$filter = "*[System[$eventProviderFilter $dateTimeFilter $eventIdFilter]]"
### Use -Verbose to debug the FilterXPath
Write-Verbose "XPath filter = $filter"

#
# More strings: patterns to look for
#

# Match AutoNGEN native image file path
$AutoNGENPattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\AppData\\Local\\Packages\\.*\\NATIVEIMAGES\\.*\.NI\.(EXE|DLL)$"

# PowerShell script-policy-test file - PS creates files in user temp directory and tests against whitelisting policy to determine whether to run in ConstrainedLanguage mode.
# Filter out those test files by default.
# Current implementation: match partial path of file in temp directory with form "XXXXXXXX.XXX.PS*" or "__PSScriptPolicyTest_XXXXXXXX.XXX.PS*"
$PsPolicyTestPattern = "\\APPDATA\\LOCAL\\TEMP\\(__PSScriptPolicyTest_)?[A-Z0-9]{8}\.[A-Z0-9]{3}\.PS"
$PsPolicyTestFileHash1 = "0x6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B"
$PsPolicyTestFileHash2 = "0x96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7"
<# Implementation notes: attempts to match against a fixed hash value instead of a somewhat complex pattern match.
    PS script policy test file used to be a one-byte file containing "1", with SHA256 hash = 0x6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B
    That ended up colliding with some other Microsoft-catalog-signed file on some machines. Signature check came up positive and test file was allowed, so
    PS consoles ran in FullLanguage mode instead of ConstrainedLanguage. PS responded by randomizing the files' content, which avoided the collision but made a hash
    comparison impossible. Current version now contains fixed content with a SHA256 hash = 0x96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7.
    Don't know how widely-deployed this is, though. For now, sticking with filepath pattern match.
    Note: as of 17 June 2019, still seeing both hashes in different environments.
#>

# Filepath pattern that can be replaced by %PUBLIC%
$PublicPattern       = "^(%OSDRIVE%|C:)\\Users\\Public\\"
# Filepath pattern that can be replaced by %LOCALAPPDATA%
$LocalAppDataPattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\AppData\\Local\\"
# Filepath pattern that can be replaced by %APPDATA%
$RoamingAppDataPattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\AppData\\Roaming\\"
# Filepath pattern that can be replaced by %USERPROFILE% (after the above already done)
$UserProfilePattern  = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\"
# FIlepath pattern that can be replaced by %PROGRAMDATA%
$ProgramDataPattern  = "^(%OSDRIVE%|C:)\\ProgramData\\"

# Tab-delimited CSV headers
$headers =
    "Location"      + "`t" +
    "GenericPath"   + "`t" +
    "GenericDir"    + "`t" +
    "OriginalPath"  + "`t" +
    "FileName"      + "`t" +
    "FileExt"       + "`t" +
    "FileType"      + "`t" +
    "PublisherName" + "`t" +
    "ProductName"   + "`t" +
    "BinaryName"    + "`t" +
    "FileVersion"   + "`t" +
    "Hash"          + "`t" +
    "UserSID"       + "`t" +
    "UserName"      + "`t" +
    "MachineName"   + "`t" +
    "EventTime"     + "`t" +
    "EventTimeXL"   + "`t" +
    "PID"           + "`t" +
    "EventType"

#
# Retrieve events
#
# Could change these Get-WinEvent calls to pass the full $EvtxLogFilePaths or $eventLogs arrays in one go instead of in a loop. *Maybe* better perf at the expense of less progress feedback.
[System.Collections.ArrayList]$ev = @()
if ($EvtxLogFilePaths)
{
    $EvtxLogFilePaths | foreach {
        Write-Host "Calling Get-WinEvent -Path $_ ..." -ForegroundColor Cyan
        # Always ensure that $oEvents is an array, whether it contains 0, 1, or more items
        $oEvents = @(Get-WinEvent -Path $_ -FilterXPath $filter -ErrorAction SilentlyContinue -ErrorVariable gweErr)
        if ($gweErr.Count -gt 0)
        {
            $gweErr | foreach { Write-Host ("--> " + $_.ToString()) -ForegroundColor Cyan }
        }
        $ev.AddRange($oEvents)
    }
}
else
{
    $eventLogs | foreach {
        if ($ComputerName)
        {
            Write-Host "Calling Get-WinEvent -LogName $_ -ComputerName $ComputerName ..." -ForegroundColor Cyan
            # Always ensure that $oEvents is an array, whether it contains 0, 1, or more items
            $oEvents = @(Get-WinEvent -LogName $_ -ComputerName $ComputerName -FilterXPath $filter -ErrorAction SilentlyContinue -ErrorVariable gweErr)
        }
        else
        {
            Write-Host "Calling Get-WinEvent -LogName $_ ..." -ForegroundColor Cyan
            # Always ensure that $oEvents is an array, whether it contains 0, 1, or more items
            $oEvents = @(Get-WinEvent -LogName $_ -FilterXPath $filter -ErrorAction SilentlyContinue -ErrorVariable gweErr)
        }
        if ($gweErr.Count -gt 0)
        {
            $gweErr | foreach { Write-Host ("--> " + $_.ToString()) -ForegroundColor Cyan }
        }
        $ev.AddRange($oEvents)
    }
}
Write-Host ($ev.Count.ToString() + " events retrieved.") -ForegroundColor Cyan

#
# Create output array; add CSV headers
#
[System.Collections.ArrayList]$csv = @()
$csv.Add($headers) | Out-Null

#
# Lookups
#
$SidToName = @{}
$AllMachineNames = @{}
$ReportedMachines = @{}

#
# Function performs SID-to-name lookups, stores results for later retrieval so the same SID isn't looked up more than once.
#
function SidToNameLookup([string]$sid)
{
    if ($SidToName.ContainsKey($sid))
    {
        $SidToName[$sid]
    }
    else
    {
        $oSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $oUser = $null
        try { $oUser = $oSID.Translate([System.Security.Principal.NTAccount]) } catch {}
        if ($null -ne $oUser)
        {
            $name = $oUser.Value
        }
        elseif ($sid.EndsWith("-500"))
        {
            $name = "[[[built-in local admin]]]";
        }
        else
        {
            $name = "[[[Not translated]]]"
        }
        $SidToName.Add($sid, $name)
        $name
    }
}

#
# Produce output
#
$count = 0
$filteredOut = 0
$oLines = @(
    $ev | foreach {

        # Whether to filter out this particular event from the output
        $filterOut = $false

        # Determine whether it's a Windows Event Collector bookmark event
        $isWecBkmark = $_.Id -eq $WecBkmarkEventID
        # Determine whether it's an APPX event
        $isAppxEvent = $_.Id -in $AppxEventIDs
        # If it's neither a WEC bookmark nor an APPX event, it's expected to be EXE, DLL, MSI, or SCRIPT

        $machineName = $_.MachineName
        $origPath = $null

        if ($isWecBkmark)
        {
            # Bookmark event; filter out this event (but capture machine info)
            $filterOut = $true
        }
        else
        {
            # Retrieve all properties at once; don't process them unless/until needed
            if (!$isAppxEvent)
            {
                $SelectorStrings = [string[]]@(
                    'Event/UserData/RuleAndFileData/PolicyName',      # 0
                    'Event/UserData/RuleAndFileData/TargetUser',      # 1
                    'Event/UserData/RuleAndFileData/TargetProcessId', # 2
                    'Event/UserData/RuleAndFileData/Fqbn',            # 3
                    'Event/UserData/RuleAndFileData/FilePath',        # 4 <-- for not APPX
                    'Event/UserData/RuleAndFileData/FileHash'         # 5 <-- for not APPX
                )
            }
            else
            {
                $SelectorStrings = [string[]]@(
                    'Event/UserData/RuleAndFileData/PolicyName',      # 0
                    'Event/UserData/RuleAndFileData/TargetUser',      # 1
                    'Event/UserData/RuleAndFileData/TargetProcessId', # 2
                    'Event/UserData/RuleAndFileData/Fqbn',            # 3
                    'Event/UserData/RuleAndFileData/Package'          # 4 <-- for APPX
                )
            }

            $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($SelectorStrings)

            $Properties = $_.GetPropertyValues($PropertySelector)

            # PolicyName (EXE, DLL, MSI, SCRIPT, APPX)
            $filetype = $Properties[0]

            if (!$isAppxEvent)
            {
                $origPath = $Properties[4]
                $oHash = $Properties[5]
                if ($oHash -is [System.String])
                {
                    if ($oHash.StartsWith("0x")) 
                    { 
                        $hash = $oHash 
                    }
                    else 
                    { 
                        $hash = "0x" + $oHash 
                    }
                }
                else
                {
                    if ($oHash.Length -gt 0)
                    {
                        $hash = "0x" + [System.BitConverter]::ToString( $oHash ).Replace('-', '')
                    }
                    else
                    {
                        $hash = "(not reported)"
                    }
                }

                # Filter out events that match patterns; do the match only if relevant for the file type
                if ($filetype -eq "SCRIPT" -and !$NoPSFilter)
                {
                    # PowerShell policy-test file (filtered out by default); 
                    # assume that string match is faster than regular expression match so try those first
                    if     ($hash -eq $PsPolicyTestFileHash1) { $filterOut = $true }
                    elseif ($hash -eq $PsPolicyTestFileHash2) { $filterOut = $true }
                    elseif ($origPath -match $PsPolicyTestPattern) { $filterOut = $true }
                }
                elseif ($filetype -in ("EXE", "DLL") -and $NoAutoNGEN)
                {
                    # AutoNGEN (not filtered out by default)
                    $filterOut = ($origPath -match $AutoNGENPattern)
                }
            }
        }

        if ($filterOut) { $filteredOut++ }

        # Unless not reporting on machines with no events, capture machine name so we can report that it's receiving policy.
        if (!$NoFilteredMachines)
        {
            # Capture some information about observed machines, in case all events related to the computer are filtered.
            if (!$AllMachineNames.ContainsKey($machineName))
            {
                # All observed machines
                $AllMachineNames.Add($machineName, "")
            }
            if (!$filterOut -and !$ReportedMachines.ContainsKey($machineName))
            {
                # Machines that have had data reported
                $ReportedMachines.Add($machineName, "")
            }
        }

        # If not filtered out, build out the event data
        if (!$filterOut)
        {
            # Computer name already in $machineName
            # high-granularity date/time where alpha sort = chronological sort; granularity = ten millionths of a second
            $timeCreated = $_.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffffff") 
            # Date/time format that Excel recognizes as date/time
            #TODO: Verify that regional preferences don't interfere with making this useful...
            $timeCreatedXL = $timeCreated.Replace("T", " ").Substring(0, 19)

            # Manual text conversion in case LevelDisplayName is not populated
            if(![string]::IsNullOrEmpty($_.LevelDisplayName)){
                $eventType = $_.LevelDisplayName  # Event type (Information, Warning, Error)
            }
            else{
                $eventType = switch($_.Level)
                {
                    1 { "Critical" }
                    2 { "Error" }
                    3 { "Warning" }
                    4 { "Information" }
                    5 { "Verbose" }
                    default { $_.Level.ToString() }
                }
            }

            $userSid = $Properties[1].ToString()
            $username = SidToNameLookup -sid $userSid
            $sPID = $Properties[2].ToString()
            if ($Properties[3] -eq "-")
            {
                $pubName = $sUnsigned
                $prodName = $binaryName = $filever = [string]::Empty
            }
            else
            {
                # Break up Fqdn publisher info
                $pubInfo = $Properties[3].Split("\") # Publisher info, separated with backslashes
                $pubName = $pubInfo[0]               # Publisher name
                $prodName = $pubInfo[1]              # Product name (syntax works even if array not this long)
                $binaryName = $pubInfo[2]            # Original "binary" name (syntax works even if array not this long)
                $filever = $pubInfo[3]               # File version (syntax works even if array not this long)
            }

            if ($isAppxEvent)
            {
                $origPath = $Properties[4]
                $filename = $genpath = $gendir = $origPath
                $fileext = [string]::Empty
                $hash = "N/A"
                $location = "Packaged app"
            }
            else
            {
                # Already got $origPath earlier
                $filename = [System.IO.Path]::GetFileName($origPath)
                $fileext = [System.IO.Path]::GetExtension($origPath)
                # Generic path replaces user-specific paths with more generic variable syntax.
                # Userprofile has to be performed after more specific appdata replacements, and Public before then.
                $genpath = ((((( $origPath                              `
                    -replace $ProgramDataPattern,    "%PROGRAMDATA%\")  `
                    -replace $PublicPattern,         "%PUBLIC%\")       `
                    -replace $LocalAppDataPattern,   "%LOCALAPPDATA%\") `
                    -replace $RoamingAppDataPattern, "%APPDATA%\")      `
                    -replace $UserProfilePattern,    "%USERPROFILE%\")
                $gendir = [System.IO.Path]::GetDirectoryName($genpath)
                if ($gendir.StartsWith("%PUBLIC%"))
                {
                    $location = "Public profile"
                }
                elseif ($gendir.StartsWith("%APPDATA%") -or $gendir.StartsWith("%LOCALAPPDATA%") -or $gendir.StartsWith("%USERPROFILE%"))
                {
                    $location = "User profile"
                }
                elseif ($gendir.StartsWith("%PROGRAMDATA%"))
                {
                    $location = "ProgramData"
                }
                elseif ($gendir.StartsWith("%HOT%") -or $gendir.StartsWith("%REMOVABLE%"))
                {
                    $location = "Hot/Removable"
                }
                elseif ($gendir.StartsWith("\\") -or ($genPath.Substring(1, 2) -eq ":\"))
                {
                    $location = "Drive/UNC"
                }
                elseif ($gendir.StartsWith("%WINDIR%") -or $gendir.StartsWith("%SYSTEM32%") -or $gendir.StartsWith("%PROGRAMFILES%"))
                {
                    $location = "Windir/ProgramFiles"
                }
                elseif ($gendir.StartsWith("%OSDRIVE%"))
                {
                    $location = "Non-default root"
                }
                else
                {
                    $location = "Other"
                }
            }

            # Output tab-delimited CSV (faster to do this and then convert to objects later than to create objects to begin with)
            # Also, this avoids having dquotes around everything.
            $location      + "`t" +
            $genpath       + "`t" +
            $gendir        + "`t" +
            $origPath      + "`t" +
            $filename      + "`t" +
            $fileext       + "`t" +
            $filetype      + "`t" +
            $pubName       + "`t" +
            $prodName      + "`t" +
            $binaryName    + "`t" +
            $filever       + "`t" +
            $hash          + "`t" +
            $userSID       + "`t" +
            $username      + "`t" +
            $machineName   + "`t" +
            $timeCreated   + "`t" +
            $timeCreatedXL + "`t" +
            $sPID          + "`t" +
            $eventType
        }

        $count++
        if ($count -eq 100)
        {
            Write-Host "." -NoNewline -ForegroundColor Cyan
            $count = 0
        }
    } | Sort-Object
)
$csv.AddRange($oLines)

#
# Unless specified otherwise, also output "empty" events for machines for which all events were filtered out
#
if (!$NoFilteredMachines)
{
    $oLines = @(
        $AllMachineNames.Keys | Sort-Object | foreach {
            $machineName = $_
            # If machine observed but not reported, report it now
            if (!$ReportedMachines.ContainsKey($machineName))
            {
                # Output the data as CSV
                <# Location      #>  "" + "`t" +
                <# GenericPath   #>  "" + "`t" +
                <# GenericDir    #>  "" + "`t" +
                <# OriginalPath  #>  "" + "`t" +
                <# FileName      #>  "" + "`t" +
                <# FileExt       #>  "" + "`t" +
                <# FileType      #>  "NONE" + "`t" +
                <# PublisherName #>  "" + "`t" +
                <# ProductName   #>  "" + "`t" +
                <# BinaryName    #>  "" + "`t" +
                <# FileVersion   #>  "" + "`t" +
                <# Hash          #>  "" + "`t" +
                <# UserSID       #>  "" + "`t" +
                <# UserName      #>  "" + "`t" +
                <# MachineName   #>  $machineName + "`t" +
                <# EventTime     #>  "" + "`t" +
                <# EventTimeXL   #>  "" + "`t" +
                <# PID           #>  "" + "`t" +
                <# EventType     #>  $sFiltered
            }
        }
    )
    $csv.AddRange($oLines)
}

Write-Host "" # New line after the dots
Write-Host "$filteredOut events filtered out." -ForegroundColor Cyan

if ($Excel)
{
    if (CreateExcelApplication)
    {
        AddWorksheetFromCsvData -csv $csv -tabname "AppLocker events"
        ReleaseExcelApplication
    }
}
elseif ($Objects)
{
    # Output PSCustomObjects to pipeline
    $csv | ConvertFrom-Csv -Delimiter "`t"
}
else
{
    # Output tab-delimited CSV text to pipeline
    $csv
}

<#
    One template for "EXE and DLL" and "MSI and Script" 8002, 8003, 8004, 8005, 8006, and 8007 events:
    <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
      <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="PolicyNameBuffer" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
      <data name="RuleId" inType="win:GUID" outType="xs:GUID"/>
      <data name="RuleNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="RuleNameBuffer" inType="win:UnicodeString" outType="xs:string" length="RuleNameLength"/>
      <data name="RuleSddlLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="RuleSddlBuffer" inType="win:UnicodeString" outType="xs:string" length="RuleSddlLength"/>
      <data name="TargetUser" inType="win:SID" outType="xs:string"/>
      <data name="TargetProcessId" inType="win:UInt32" outType="win:PID"/>
      <data name="FilePathLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="FilePathBuffer" inType="win:UnicodeString" outType="xs:string" length="FilePathLength"/>
      <data name="FileHashLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="FileHash" inType="win:Binary" outType="xs:hexBinary" length="FileHashLength"/>
      <data name="FqbnLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="Fqbn" inType="win:UnicodeString" outType="xs:string" length="FqbnLength"/>
      <data name="TargetLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
    </template>

    One template for "Packaged app-Execution" 8020, 8021, and 8022 events:
    <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
      <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="PolicyNameBuffer" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
      <data name="RuleId" inType="win:GUID" outType="xs:GUID"/>
      <data name="RuleNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="RuleNameBuffer" inType="win:UnicodeString" outType="xs:string" length="RuleNameLength"/>
      <data name="RuleSddlLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="RuleSddlBuffer" inType="win:UnicodeString" outType="xs:string" length="RuleSddlLength"/>
      <data name="TargetUser" inType="win:SID" outType="xs:string"/>
      <data name="TargetProcessId" inType="win:UInt32" outType="win:PID"/>
      <data name="PackageLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="PackageBuffer" inType="win:UnicodeString" outType="xs:string" length="PackageLength"/>
      <data name="FqbnLength" inType="win:UInt16" outType="xs:unsignedShort"/>
      <data name="Fqbn" inType="win:UnicodeString" outType="xs:string" length="FqbnLength"/>
    </template>

    Event ID 111 with $_.ProviderName -eq "Microsoft-Windows-EventForwarder" indicates an artificial
    event created on the Windows event collector when a client system creates a subscription.
    Use it to identify systems that were able to forward events but didn't.
    Example event XML:
    <?xml version="1.0"?>
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
        <Provider Name="Microsoft-Windows-EventForwarder"/>
        <EventID>111</EventID>
        <TimeCreated SystemTime="2018-03-02T21:04:42.797Z"/>
        <Computer>myworkstation.contoso.com</Computer>
        </System>
        <SubscriptionBookmarkEvent>
        <SubscriptionId/>
        </SubscriptionBookmarkEvent>
    </Event>
#>
