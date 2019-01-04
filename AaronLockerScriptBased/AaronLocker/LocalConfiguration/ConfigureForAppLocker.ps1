<#
.SYNOPSIS
Basic one-time single-computer configuration changes for AppLocker.
Requires administrative rights.

.DESCRIPTION
Configures the Application Identity service (appidsvc) for automatic start
Starts the Application Identity service
Sets the maximum log size for each of the AppLocker event logs to 1GB.

#>

# Configure AppIdSvc for Automatic start
SC.EXE config AppIdSvc start= auto

# Start the service if not already running
SC.exe start appidsvc

# Set the primary AppLocker event log sizes to 1GB

$logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.MaximumSizeInBytes = (1024 * 1024 * 1024)
$log.SaveChanges()

$logName = 'Microsoft-Windows-AppLocker/MSI and Script'
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.MaximumSizeInBytes = (1024 * 1024 * 1024)
$log.SaveChanges()

#These event logs don't exist on Windows 7: ignore any errors.
try
{
    $logName = 'Microsoft-Windows-AppLocker/Packaged app-Deployment'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.MaximumSizeInBytes = (1024 * 1024 * 1024)
    $log.SaveChanges()

    $logName = 'Microsoft-Windows-AppLocker/Packaged app-Execution'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.MaximumSizeInBytes = (1024 * 1024 * 1024)
    $log.SaveChanges()
}
catch {}
