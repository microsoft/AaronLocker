<#
.SYNOPSIS
Retrieves and sorts event data from AppLocker logs, removes duplicates, and reports as tab-delimited CSV output, PSCustomObjects, or as an Excel worksheet.

TODO: Add support for "Packaged app-Execution"

.DESCRIPTION
Any fields can be omitted from the output; removing fields with unique data such as event time can result
in removal of more lines that otherwise contain duplicated data.

AppLocker logs can be saved event log files, or live event logs on the local or a named remote computer.

Output can be tab-delimited CSV, an array of PSCustomObject, or a formatted Excel worksheet.

By default, retrieves error and warning events from both the EXE/DLL and MSI/Script event logs on the local computer.
Live-log options include reading events from a remote computer, reading from one of the EXE/DLL and MSI/Script logs
instead of both, or reading from the "Forwarded Events" event log on the local or a remote computer.
Optionally, read from one or more saved .evtx files.

By default, retrieves error and warning events. AppLocker in audit mode produces warning events ("would have been blocked"), while enforce mode produces error events ("was blocked").
Optionally, read just errors, just warnings, just information events (file was allowed), or all events.

Data from each event (minus any omitted fields) is turned into a line of tab-delimited CSV. These lines are then sorted
and duplicates are removed. When fields containing more unique data are omitted, the remaining data will tend to have more
duplication and more lines will be removed. See the detailed parameter descriptions for more information.

Random-named temporary files created by PowerShell to test whitelisting policy are filtered out by default.

Use the -ComputerName parameter to name a remote computer from which to retrieve events.
Use the -WarningOnly, -ErrorOnly, -Allowed, or -AllEvents switches to retrieve events other than errors+warnings.
Use the -ExeAndDllOnly or -MsiAndScriptOnly switches to retrieve events only from one of the two live event logs.
Use the -ForwardedEvents switch to read from the ForwardedEvents log instead of from the EXE/DLL and MSI/Script logs.
Use the -EvtxLogFilePaths parameter to name one or more saved event log files to read.
Use the -NoPsFilter switch not to filter out random-named PowerShell policy test script files.
Use the other -No* switches to omit fields from the output. -NoEventTime, -NoEventTimeXL, and -NoPID are the most important for reducing output size.

See the detailed parameter descriptions for more information.

.PARAMETER ComputerName
Inspects events on the named remote computer instead of the local computer. Caller must have administrative rights on the remote computer.

.PARAMETER ExeAndDllOnly
Retrieves only from the EXE and DLL log (doesn't retrieve from the MSI and Script log).
If neither -ExeAndDllOnly or -MsiAndScriptOnly are specified, retrieves from both logs.

.PARAMETER MsiAndScriptOnly
Retrieves only from the MSI and Script log (doesn't retrieve from the EXE and DLL log).
If neither -ExeAndDllOnly or -MsiAndScriptOnly are specified, retrieves from both logs.

.PARAMETER ForwardedEvents
Retrieves from the ForwardedEvents log instead of from the EXE/DLL and MSI/Script logs.

.PARAMETER EvtxLogFilePaths
Specifies path to one or more saved event log files. (Cannot be used with -ComputerName, -ExeAndDllOnly, or -MsiAndScriptOnly.)

.PARAMETER WarningOnly
Reports only Warning events (AuditOnly mode; "would have been blocked"), instead of Errors + Warnings.

.PARAMETER ErrorOnly
Reports only Error events (Enforce mode; files actually blocked), instead of Errors + Warnings.

.PARAMETER Allowed
Reports only Information events (files allowed to run) instead of Errors + Warnings.

.PARAMETER AllEvents
Reports all Information, Warning, and Error events.

.PARAMETER FromDateTime
Reports only events on or after the specified date or date-time. E.g., -FromDateTime "9/7/2017" or -FromDateTime "9/7/2017 12:00:00"
Can be used with -ToDateTime to specify a date/time range. Date/time specified in local time zone.

.PARAMETER ToDateTime
Reports only events on or before the specified date or date-time. E.g., -ToDateTime "9/7/2017" or -ToDateTime "9/7/2017 12:00:00"
Can be used with -FromDateTime to specify a date/time range. Date/time specified in local time zone.

.PARAMETER NoGenericPath
GenericPath is the original file path with "%LOCALAPPDATA%" replacing the beginning of the path name if it matches the typical pattern "C:\Users\[username]\AppData\Local".
Makes similar replacements for "%APPDATA%" or "%USERPROFILE%" if LOCALAPPDATA isn't applicable.
If -NoGenericPath is specified, GenericPath data is not included in the output.

.PARAMETER NoGenericDir
GenericDir is the directory-name portion of GenericPath (i.e., with the filename removed).
If -NoGenericDir is specified, GenericDir data is not included in the output.

.PARAMETER NoOriginalPath
OriginalPath is the file path exactly as reported in the AppLocker event log data.
If a file is used by multiple users, OriginalPath often includes differentiating information such as user profile name.
If -NoOriginalPath is specified, OriginalPath data is not included in the output. This can be useful when aggregating data from many users running the same programs.

.PARAMETER NoFileName
FileName is the logged filename (including extension) by itself without path information.
If -NoFileName is specified, FileName data is not included in the output.

.PARAMETER NoFileExt
FileExt is the file extension of the logged file. This can be useful to track files with non-standard file extensions.
If -NoFileExt is specified, FileExt data is not included in the output.

.PARAMETER NoFileType
FileType is "EXE," "DLL," "MSI," or "SCRIPT."
If -NoFileType is specified, FileType data is not included in the output.

.PARAMETER NoPublisherName
For signed files, PublisherName is the distinguished name (DN) of the file's digital signer. PublisherName is blank or just a hyphen if the file is not signed by a trusted publisher.
If -NoPublisherName is specified, PublisherName data is not included in the output.

.PARAMETER NoProductName
For signed files, ProductName is the product name taken from the file's version resource.
If -NoProductName is specified, ProductName data is not included in the output.

.PARAMETER NoBinaryName
For signed files, BinaryName is the "OriginalName" field taken from the file's version resource.
If -NoBinaryName is specified, BinaryName data is not included in the output.

.PARAMETER NoFileVersion
For signed files, FileVersion is the binary file version taken from the file's version resource.
If -NoFileVersion is specified, FileVersion data is not included in the output.

.PARAMETER NoHash
The Hash field, if included, represents the file's SHA256 hash. In addition to being incorporated in rule data, the hash data can help determine whether two files are identical.
If -NoHash is specified, the file's SHA256 hash data is not included in the output.

.PARAMETER NoUserSID
UserSID is the security identifier (SID) of the user that ran or tried to run the file.
If -NoUserSID is specified, UserSID data is not included in the output.
If a file is used by different users, UserSID is differentiating. -NoUserSID can be useful when aggregating data from many users running the same programs.

.PARAMETER NoUserName
UserName is the result of SID-to-name translation of the UserSID value performed on the local computer.
If -NoUserName is specified, SID-to-name translation is not attempted and UserName data is not included in the output.
If a file is used by different users, UserName is differentiating. -NoUserName can be useful when aggregating data from many users running the same programs.

.PARAMETER NoMachineName
MachineName is the computer name on which the event was logged.
If -NoMachineName is specified, MachineName data is not included in output. This can be useful when aggregating data forwarded from many computers.

.PARAMETER NoEventTime
EventTime is the date and time that the event occurred, in the computer's local time zone and rendered in this sortable format "yyyy-MM-ddTHH:mm:ss.fffffff".
For example, June 13, 2018, 6:49pm plus 17.7210233 seconds is reported as 2018-06-13T18:49:17.7210233.
If -NoEventTime is specified, EventTime data is not included in the output. This is useful when you want to get at most one event for every file referenced.

.PARAMETER NoEventTimeXL
EventTimeXL is the date and time that the event occurred, in the computer's local time zone and rendered in a format that Excel recognizes as a date/time, and its filter dropdown renders in a tree view.
If -NoEventTimeXL is specified, EventTimeXL data is not included in the output. This is useful when you want to get at most one event for every file referenced.

.PARAMETER NoPID
PID is the process ID. It can be used to correlate EXE files and other file types, including scripts and DLLs.
If -NoPID is specified, the PID is not included in the output.
Note that a PID is a unique identifier only on the computer the process is running on and only while it is running. When the process exits, the PID value can be assigned to another process.

.PARAMETER NoEventType
EventType is "Information," "Warning," or "Error," which can be particularly helpful with -AllEvents, as it's not otherwise possible to tell whether the file was allowed.
If -NoEventType is specified, EventType data is not included in the output.

.PARAMETER NoAutoNGEN
If specified, does not report modern-app AutoNGEN files that are unsigned and in the user's profile.

.PARAMETER NoPSFilter
If specified, does not try to filter out random-named PowerShell scripts used to determine whether whitelisting is in effect.

.PARAMETER NoFilteredMachines
By default, this script outputs a single artificial "empty" event line for every machine for which all observed events were filtered out.
If -NoFilteredMachines is specified, these event lines are not output.

.PARAMETER Excel
If this optional switch is specified, outputs to a formatted Excel rather than tab-delimited CSV text to the pipeline.

.PARAMETER Objects
If this optional switch is specified, outputs PSCustomObjects rather than tab-delimited CSV. (Passes CSV through ConvertFrom-Csv.)
This switch is ignored if -Excel is also specified.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -EvtxLogFilePaths .\ForwardedEvents1.evtx, .\ForwardedEvents2.evtx -NoMachineName -NoEventTime -NoEventTimeXL

Get warning and error events from events exported into ForwardedEvents1.evtx and ForwardedEvents2.evtx; don't include MachineName or EventTime data in the output.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -NoOriginalPath -NoEventTime -NoEventTimeXL -NoUserSID | clip.exe

Get warning and error events from the EXE/DLL and MSI/Script logs on the local computer, removing user-specific and time-specific fields, with the goal that each referenced file appears at most once in the output, no matter how many users referenced it or how often. Write the output to the Windows clipboard so that it can be pasted into Microsoft Excel.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -Objects | Where-Object { [datetime]($_.EventTime) -gt "8/20/2017" }

Get warning and error events from the EXE/DLL and MSI/Script logs on the local computer since August 20, 2017.
It converts output into objects, and pipes those objects into a filter that passes only events with event dates after midnight, August 20, 2017.

.EXAMPLE
.\Get-AppLockerEvents.ps1 -FromDateTime "8/1/2017" -ToDateTime "9/1/2017"

Gets warning and error events from the EXE/DLL and MSI/Script logs on the local computer between Aug 1, 2017 00:00:00 and Sept 1, 2017 00:00:00.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -Allowed -Objects | Group-Object PublisherName

Get allowed files from the EXE/DLL and MSI/Script logs on the local computer. Convert output into objects, group the objects according to the PublisherName field.

.EXAMPLE

.\Get-AppLockerEvents.ps1 -NoOriginalPath -NoEventTime -NoEventTimeXL -NoUserSID -Objects | Where-Object { $_.PublisherName.Length -le 1 } | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation

Get warning and error events from the EXE/DLL and MSI/Script logs on the local computer, outputting only unsigned files.
It converts output into objects, filters on PublisherName length (allowing up to a hyphen in length), then converts back to tab-delimited CSV.

.EXAMPLE
$ev = .\Get-AppLockerEvents.ps1 -Objects
$ev | Select-Object UserName, MachineName -Unique | Sort-Object UserName, MachineName
$ev.FileExt | Sort-Object -Unique

Output a list of each combination of users and machines reporting events, and a list of all observed file extensions involved with events.



#>

[CmdletBinding(DefaultParameterSetName="LiveLogs")]
param(
    # Optional remote computer name
    [parameter(Mandatory=$false, ParameterSetName="LiveLogs")]
    [String]
    $ComputerName,

    # Which event log(s) to inspect (default is EXE/DLL and MSI/Script logs)
    [parameter(ParameterSetName="LiveLogs")]
    [switch]
    $ExeAndDllOnly = $false,
    [parameter(ParameterSetName="LiveLogs")]
    [switch]
    $MsiAndScriptOnly = $false,
    [parameter(ParameterSetName="LiveLogs")]
    [switch]
    $ForwardedEvents = $false,

    [parameter(Mandatory=$false, ParameterSetName="SavedLogs")]
    [String[]]
    $EvtxLogFilePaths,

    # Which event types to inspect (default is warnings + errors)
    [switch]
    $WarningOnly = $false,
    [switch]
    $ErrorOnly = $false,
	[switch]
	$Allowed = $false,
    [switch]
    $AllEvents = $false,

    # Optional date range
    [parameter(Mandatory=$false)]
    [datetime]
    $FromDateTime,
    [parameter(Mandatory=$false)]
    [datetime]
    $ToDateTime,

    # Data to return. Defaults to all, except those switched off with the following switches
    [switch]
    $NoGenericPath = $false,
    [switch]
    $NoGenericDir = $false,
    [switch]
    $NoOriginalPath = $false,
    [switch]
    $NoFileName = $false,
    [switch]
    $NoFileExt = $false,
    [switch]
    $NoFileType = $false,
    [switch]
    $NoPublisherName = $false,
    [switch]
    $NoProductName = $false,
    [switch]
    $NoBinaryName = $false,
    [switch]
    $NoFileVersion = $false,
    [switch]
    $NoHash = $false,
    [switch]
    $NoUserSID = $false,
    [switch]
    $NoUserName = $false,
    [switch]
    $NoMachineName = $false,
    [switch]
    $NoEventTime = $false,
    [switch]
    $NoEventTimeXL = $false,
    [switch]
    $NoPID = $false,
    [switch]
    $NoEventType = $false,

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

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file.
. $rootDir\Support\Config.ps1

#
# Strings
#
$ExeDllLogName    = 'Microsoft-Windows-AppLocker/EXE and DLL'
$MsiScriptLogName = 'Microsoft-Windows-AppLocker/MSI and Script'
$FwdEventsLogName = 'ForwardedEvents'
$ExeDllAllowed    = 'EventID=8002'
$ExeDllWarning    = 'EventID=8003'
$ExeDllError      = 'EventID=8004'
$MsiScriptAllowed = 'EventID=8005'
$MsiScriptWarning = 'EventID=8006'
$MsiScriptError   = 'EventID=8007'
$SubscriptionBkmrk= 'EventID=111'

#
# Event logs to query
#
$eventLogs = @()

#
# Specify event log names to query.
# If looking at ForwardedEvents, also set XPath to filter on provider so we don't inadvertently get events from sources we don't know about.
#
$eventProviderFilter = ""

if ($ForwardedEvents)
{
    $eventLogs += $FwdEventsLogName
    $eventProviderFilter = "Provider[@Name='Microsoft-Windows-AppLocker' or @Name='Microsoft-Windows-EventForwarder'] and"
}
else
{
    if (!$MsiAndScriptOnly) { $eventLogs += $ExeDllLogName }
    if (!$ExeAndDllOnly) { $eventLogs += $MsiScriptLogName }
}
if ($eventLogs.Length -eq 0 -and $EvtxLogFilePaths.Length -eq 0)
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
$eventIdFilter = "$ExeDllWarning or $MsiScriptWarning or $ExeDllError or $MsiScriptError"
if ($WarningOnly)
{
    $eventIdFilter = "$ExeDllWarning or $MsiScriptWarning"
}
if ($ErrorOnly)
{
    $eventIdFilter = "$ExeDllError or $MsiScriptError"
}
if ($Allowed)
{
    $eventIdFilter = "$ExeDllAllowed or $MsiScriptAllowed"
}
if ($AllEvents)
{
    $eventIdFilter = "$ExeDllAllowed or $MsiScriptAllowed or $ExeDllWarning or $MsiScriptWarning or $ExeDllError or $MsiScriptError"
}
if ($ForwardedEvents -and !$NoFilteredMachines)
{
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
# Match partial path in temp directory with form XXXXXXXX.XXX.PS* or __PSScriptPolicyTest_XXXXXXXX.XXX.PS*
$PsPolicyTestPattern = "\\APPDATA\\LOCAL\\TEMP\\(__PSScriptPolicyTest_)?[A-Z0-9]{8}\.[A-Z0-9]{3}\.PS"
# Usage:
#     if ($origPath -match $PsPolicyTestPattern) { $filterOut = !$NoPSFilter }
# New implementation: PS script policy test file is a one-byte file containing "1". Its SHA256 hash is 0x6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B 
# Check for that hash rather than the filepath pattern. The hash will be reliable; the file pattern could give a false positive.
# (Perf test indicates no benefit of one test over the other.)
# NOTE: if the content of the test file changes, there will be a new hash value to test for.
# NOTE: The PowerShell folks started randomizing the content, so hash check no longer works - need to look for filename patterns.
# $PsPolicyTestFileHash = "0x6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B"
# Pattern was: if ($hash -eq $PsPolicyTestFileHash) ...

# Match AutoNGEN native image file path
$AutoNGENPattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\AppData\\Local\\Packages\\.*\\NATIVEIMAGES\\.*\.NI\.(EXE|DLL)$"

# Pattern that can be replaced by %LOCALAPPDATA%
$LocalAppDataPattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\AppData\\Local\\"
# Pattern that can be replaced by %APPDATA%
$RoamingAppDataPattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\AppData\\Roaming\\"
# Pattern that can be replaced by %USERPROFILE% (after the above already done)
$UserProfilePattern  = "^(%OSDRIVE%|C:)\\Users\\[^\\]*\\"

# Tab
$t = "`t"

# Properties
$props = @()
if (!$NoGenericPath)   { $props += "GenericPath" }
if (!$NoGenericDir)    { $props += "GenericDir" }
if (!$NoOriginalPath)  { $props += "OriginalPath" }
if (!$NoFileName)      { $props += "FileName" }
if (!$NoFileExt)       { $props += "FileExt" }
if (!$NoFileType)      { $props += "FileType" }
if (!$NoPublisherName) { $props += "PublisherName" }
if (!$NoProductName)   { $props += "ProductName" }
if (!$NoBinaryName)    { $props += "BinaryName" }
if (!$NoFileVersion)   { $props += "FileVersion" }
if (!$NoHash)          { $props += "Hash" }
if (!$NoUserSID)       { $props += "UserSID" }
if (!$NoUserName)      { $props += "UserName" }
if (!$NoMachineName)   { $props += "MachineName" }
if (!$NoEventTime)     { $props += "EventTime" }
if (!$NoEventTimeXL)   { $props += "EventTimeXL" }
if (!$NoPID)           { $props += "PID" }
if (!$NoEventType)     { $props += "EventType" }
$headers = $props -join $t

#
# Retrieve events
#
$ev = @()
if ($EvtxLogFilePaths)
{
    $EvtxLogFilePaths | foreach {
        Write-Host "Calling Get-WinEvent -Path $_ ..." -ForegroundColor Cyan
        $ev += Get-WinEvent -Path $_ -FilterXPath $filter -ErrorAction SilentlyContinue -ErrorVariable gweErr
        if ($gweErr.Count -gt 0)
        {
            $gweErr | foreach { Write-Host ("--> " + $_.ToString()) -ForegroundColor Cyan }
        }
    }
}
else
{
    $eventLogs | foreach {
        if ($ComputerName)
        {
            Write-Host "Calling Get-WinEvent -LogName $_ -ComputerName $ComputerName ..." -ForegroundColor Cyan
            $ev += (Get-WinEvent -LogName $_ -ComputerName $ComputerName -FilterXPath $filter -ErrorAction SilentlyContinue -ErrorVariable gweErr)
        }
        else
        {
            Write-Host "Calling Get-WinEvent -LogName $_ ..." -ForegroundColor Cyan
            $ev += (Get-WinEvent -LogName $_ -FilterXPath $filter -ErrorAction SilentlyContinue -ErrorVariable gweErr)
        }
        if ($gweErr.Count -gt 0)
        {
            $gweErr | foreach { Write-Host ("--> " + $_.ToString()) -ForegroundColor Cyan }
        }
    }
}
Write-Host ($ev.Count.ToString() + " events retrieved.") -ForegroundColor Cyan

#TODO: Figure out whether/when only one works, and why: Xml vs. Get-WinEvent objects
$UseXml = $true

#
# Create output array; add CSV headers
#
$csv = @()
$csv += $headers

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
$csv += (
    $ev | foreach {

        # Implement options to hide items that match PowerShell policy test script or AutoNGEN native images:
        $filterOut = $false

        <#
            Event ID 111 (should maybe also check $_.ProviderName -eq "Microsoft-Windows-EventForwarder") indicates an artificial
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
        if ($_.Id -eq 111)
        {
            # Bookmark event
            $filterOut = $true
        }
        else
        {
            $xEv = $null
            $xData = $null
    
            if ($UseXml -or $null -eq $_.Properties[0])
            {
                $xEv = [xml]($_.ToXml())
                $xData = $xEv.Event.UserData.RuleAndFileData
                $origPath = $xData.FilePath
                $hash = "0x" + $xData.FileHash
                $sPID = $xData.TargetProcessId
            }
            else
            {
                $origPath = $_.Properties[10].Value               # File path
                $hash = "0x" + [System.BitConverter]::ToString( $_.Properties[12].Value ).Replace('-', '')
                $sPID = $_.Properties[8].Value
            }

            if ($origPath -match $PsPolicyTestPattern)
            {
                $filterOut = !$NoPSFilter
            }
            elseif ($origPath -match $AutoNGENPattern)
            {
                $filterOut = $NoAutoNGEN
            }
        }

        if ($filterOut) { $filteredOut++ }

        if (!$NoFilteredMachines)
        {
            # Observed machines
            $machineName = $_.MachineName                 # Computer name
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

        if (!$filterOut)
        {
            $timeCreated = $_.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffffff") # alpha sort = chronological sort; granularity = ten millionths of a second
            $machineName = $_.MachineName                 # Computer name

            # Manual text conversion in case LevelDisplayName is not populated
            if(![string]::IsNullOrEmpty($_.LevelDisplayName)){
                $eventType   = $_.LevelDisplayName            # Event type (Information, Warning, Error)
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

            if ($null -eq $xData)
            {
                $filetype = $_.Properties[1].Value            # EXE, DLL, MSI, or SCRIPT
                $userSid = $_.Properties[7].Value.Value       # User SID (System.Security.Principal.SecurityIdentifier)
                $pubInfo = $_.Properties[14].Value.Split("\") # Publisher info, separated with backslashes
                # $hash = "0x" + [System.BitConverter]::ToString( $_.Properties[12].Value ).Replace('-', '')
            }
            else
            {
                $filetype = $xData.PolicyName
                $userSid = $xData.TargetUser
                $pubInfo = $xData.Fqbn.Split("\")
                # $hash = "0x" + $xData.FileHash
            }

            $pubName = $pubInfo[0]                        # Publisher name
            $prodName = $pubInfo[1]                       # Product name (syntax works even if array not this long)
            $binaryName = $pubInfo[2]                     # Original "binary" name (syntax works even if array not this long)
            $filever = $pubInfo[3]                        # File version (syntax works even if array not this long)
            $filename = [System.IO.Path]::GetFileName($origPath)
            $fileext = [System.IO.Path]::GetExtension($origPath)
            # Generic path replaces user-specific paths with more generic variable syntax.
            # Userprofile has to be performed after more specific appdata replacements.
            $genpath = (($origPath -replace $LocalAppDataPattern, "%LOCALAPPDATA%\") -replace $RoamingAppDataPattern, "%APPDATA%\") -replace $UserProfilePattern, "%USERPROFILE%\"
            $gendir = [System.IO.Path]::GetDirectoryName($genpath)

            #Anyone wants objects, they can ConvertFrom-Csv.
            $data = @()
            if (!$NoGenericPath)   { $data += $genpath }
            if (!$NoGenericDir)    { $data += $gendir }
            if (!$NoOriginalPath)  { $data += $origPath }
            if (!$NoFileName)      { $data += $filename }
            if (!$NoFileExt)       { $data += $fileext }
            if (!$NoFileType)      { $data += $filetype }
            if (!$NoPublisherName) { $data += $pubName }
            if (!$NoProductName)   { $data += $prodName }
            if (!$NoBinaryName)    { $data += $binaryName }
            if (!$NoFileVersion)   { $data += $filever }
            if (!$NoHash)          { $data += $hash }
            if (!$NoUserSID)       { $data += $userSID }
            if (!$NoUserName)      { $data += SidToNameLookup $userSid }
            if (!$NoMachineName)   { $data += $machineName }
            if (!$NoEventTime)     { $data += $timeCreated }
            #TODO: Verify that regional preferences don't interfere with making this useful...
            if (!$NoEventTimeXL)   { $data += $timeCreated.Replace("T", " ").Substring(0, 19) }
            if (!$NoPID)           { $data += $sPID }
            if (!$NoEventType)     { $data += $eventType }
            # Output the data as CSV
            $data -join $t
        }

        $count++
        if ($count -eq 100)
        {
            Write-Host "." -NoNewline -ForegroundColor Cyan
            $count = 0
        }
    } | Sort-Object -Unique
)

#
# Unless specified otherwise, also output "empty" events for machines for which all events were filtered out
#
if (!$NoFilteredMachines)
{
    $csv += (
        $AllMachineNames.Keys | Sort-Object | foreach {
            $machineName = $_
            # If machine observed but not reported, report it now
            if (!$ReportedMachines.ContainsKey($machineName))
            {
                $data = @()
                if (!$NoGenericPath)   { $data += "" }
                if (!$NoGenericDir)    { $data += "" }
                if (!$NoOriginalPath)  { $data += "" }
                if (!$NoFileName)      { $data += "" }
                if (!$NoFileExt)       { $data += "" }
                if (!$NoFileType)      { $data += "NONE" }
                if (!$NoPublisherName) { $data += "" }
                if (!$NoProductName)   { $data += "" }
                if (!$NoBinaryName)    { $data += "" }
                if (!$NoFileVersion)   { $data += "" }
                if (!$NoHash)          { $data += "" }
                if (!$NoUserSID)       { $data += "" }
                if (!$NoUserName)      { $data += "" }
                if (!$NoMachineName)   { $data += $machineName }
                if (!$NoEventTime)     { $data += "" }
                if (!$NoEventTimeXL)   { $data += "" }
                if (!$NoPID)           { $data += "" }
                if (!$NoEventType)     { $data += "FILTERED" }
                # Output the data as CSV
                $data -join $t
            }
        }
    )
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
    Template for 8002, 8003, and 8004 events (and 8005, 8006, and 8007):
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
#>