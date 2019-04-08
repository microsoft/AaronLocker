<#
.SYNOPSIS
Customizable script used by Create-Policies.ps1 that produces a list of "safe"
paths to allow for non-admin execution.

.DESCRIPTION
This script outputs zero or more hashtables containing information to define path rules
for files of directories that can be considered "safe" for non-admins.

The list is consumed by Create-Policies.ps1, which incorporates the paths
into AppLocker rules allowing execution of Exe, Dll, and/or Script files.

NOTE: DIRECTORY/FILE PATHS IDENTIFIED IN THIS SCRIPT SHOULD NOT BE WRITABLE
BY NON-ADMIN USERS!!!
You can edit this file as needed for your environment.

The hashtables need to have the following required properties: 
* Label: String is incorporated into the rule name and description
* Path: Path of file or directory to be whitelisted. Directories path always
  need to end with "\*"", e.g.: "C:\ProgramData\App-V\*", "\\MYSERVER\Apps\*". Individual
  files should not end with "\*".

The following properties are optional:
* RuleCollection: to apply the trust only within a single RuleCollection.
RuleCollection must be one of "Exe", "Dll", "Script", or "Msi", and it is CASE-SENSITIVE.

Specify paths using only fixed local drive letters or UNC paths. Do not use
mapped drive letters or SUBST drive letters, as the user can change their
definitions. If X: is mapped to the read-only \\MYSERVER\Apps file share,
and you allow execution in \\MYSERVER\Apps\*, the user can run MyProgram.exe
in that share whether it is referenced as \\MYSERVER\Apps\MyProgram.exe or
as X:\MyProgram.exe. Similarly, AppLocker does the right thing with
SUBSTed drive letters.

Paths may contain all supported AppLocker path variables for well-known
directories in Windows such as %WINDIR%, %SYSTEM32%, %OSDRIVE%, %PROGRAMFILES%,
%REMOVABLE% and %HOT%.

See also https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/understanding-the-path-rule-condition-in-applocker

Besides the known AppLocker path variables, the following special path
variables %USERPROFILE%, %LOCALAPPDATA% and %APPDATA% are also supported and
will substituted to  "%OSDRIVE%\Users\*", "%OSDRIVE%\Users\*\AppData\Local"
and "%OSDRIVE%\Users\*\AppData\Roaming" resp.

Examples:

@{
    Label = 'Anaconda';
    Path = '%LOCALAPPDATA%\Continuum\Anaconda3\PKGS\*';
    RuleCollection = 'Exe'
}

@{
    Label = 'App-V';
    Path = '%OSDRIVE%\App-V\*';
}

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
        @{
            Label = "DC Shares";
            Path = "\\$computerDomain\netlogon\*";
        }
        @{
            Label = "DC Shares";
            Path = "\\$computerDomain\sysvol\*";
        }
        
		$userDomain = $env:USERDNSDOMAIN
		if ($null -ne $userDomain -and $userDomain.ToUpper() -ne $computerDomain.ToUpper())
		{
            @{
                Label = "DC Shares";
                Path = "\\$userDomain\netlogon\*";
            }
            @{
                Label = "DC Shares";
                Path = "\\$userDomain\sysvol\*";
            }    
		}
    }
    else
    {
        Write-Host "Computer is not domain-joined; not adding path for DC shares." -ForegroundColor Cyan
    }
}

### Windows Defender put their binaries in ProgramData for a while. Comment this back out when they move it back.
@{
    Label = "Windows Defender";
    Path = "%OSDRIVE%\PROGRAMDATA\MICROSOFT\WINDOWS DEFENDER\PLATFORM\*";
}    

# Windows upgrade sources
@{
    Label = "Windows Upgrade";
    Path = '%OSDRIVE%\$WINDOWS.~BT\Sources\*';
}    
