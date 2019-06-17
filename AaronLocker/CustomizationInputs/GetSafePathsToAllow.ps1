<#
.SYNOPSIS
Customizable script used by Create-Policies.ps1 that produces a list of additional "safe" paths to allow for non-admin execution.

.DESCRIPTION
This script outputs a simple list of directories that can be considered "safe" for non-admins to execute programs from.
The list is consumed by Create-Policies.ps1, which incorporates the paths into AppLocker rules allowing execution of
EXE, DLL, and Script files.
NOTE: DIRECTORY/FILE PATHS IDENTIFIED IN THIS SCRIPT MUST NOT BE WRITABLE BY NON-ADMIN USERS!!!
You can edit this file as needed for your environment.

Note that each directory name must be followed by \*, as in these examples:
    "C:\ProgramData\App-V\*"
    "\\MYSERVER\Apps\*"
Individual files can be allowed by path, also. Do not end those with "\*"

Specify paths using only fixed local drive letters or UNC paths. Do not use mapped drive letters or
SUBST drive letters, as the user can change their definitions. If X: is mapped to the read-only
\\MYSERVER\Apps file share, and you allow execution in \\MYSERVER\Apps\*, the user can run MyProgram.exe
in that share whether it is referenced as \\MYSERVER\Apps\MyProgram.exe or as X:\MyProgram.exe. Similarly,
AppLocker does the right thing with SUBSTed drive letters.

TODO: At some point, reimplement with hashtable output supporting "label" and "RuleCollection" properties so that path rules have more descriptive names, and can be applied to specific rule collections.

#>

# Add the standard domain controller GPO file shares for the computer's AD domain, and if different, for the user account's domain.
# Needed to allow execution of user logon/logoff scripts. (Computer startup/shutdown scripts run as System and don't need special rules.)
# As an alternative, just output the paths explicitly; e.g., "\\corp.contoso.com\netlogon\*"
# Note that if logon scripts invoke other scripts/programs using an explicit \\DC\netlogon\ syntax, these rules won't cover them. Need
# explicit rules naming domain controllers. (I know that sucks.)
$cs = Get-CimInstance -ClassName CIM_ComputerSystem
if ($null -ne $cs)
{
    if ($cs.PartOfDomain)
    {
        $computerDomain = $cs.Domain
        "\\$computerDomain\netlogon\*"
        "\\$computerDomain\sysvol\*"
		$userDomain = $env:USERDNSDOMAIN
		if ($null -ne $userDomain -and $userDomain.ToUpper() -ne $computerDomain.ToUpper())
		{
        	"\\$userDomain\netlogon\*"
        	"\\$userDomain\sysvol\*"
		}
    }
    else
    {
        Write-Host "Computer is not domain-joined; not adding path for DC shares." -ForegroundColor Cyan
    }
}

### Windows Defender put their binaries in ProgramData for a while. Comment this back out when they move it back.
"%OSDRIVE%\PROGRAMDATA\MICROSOFT\WINDOWS DEFENDER\PLATFORM\*"

