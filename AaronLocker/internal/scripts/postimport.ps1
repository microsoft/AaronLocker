# Add all things you want to run after importing the main code

# Load Variables
. Import-ModuleFile -Path "$ModuleRoot\internal\scripts\variables.ps1"

# Register a scriptblock for use by Source File Rules
. Import-ModuleFile -Path "$ModuleRoot\internal\scripts\resolveFileRule.ps1"