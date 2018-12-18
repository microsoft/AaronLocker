<#
.SYNOPSIS
Clears events from local AppLocker event logs.
Requires administrative rights.
#>

wevtutil.exe clear-log "Microsoft-Windows-AppLocker/EXE and DLL"
wevtutil.exe clear-log "Microsoft-Windows-AppLocker/MSI and Script"
wevtutil.exe clear-log "Microsoft-Windows-AppLocker/Packaged app-Deployment"
wevtutil.exe clear-log "Microsoft-Windows-AppLocker/Packaged app-Execution"
