<#
.SYNOPSIS
Customizable script used by Create-Policies.ps1 that identifies user-writable paths containing files that need to be allowed to execute.

.DESCRIPTION
This script outputs a sequence of hashtables that identify user-writable files or directory paths containing content that users must be allowed to execute.
(The scripts favor publisher rules over hash rules.)
Each hashtable must include "label" and "paths" properties, with additional optional properties.
Hashtable properties:
* label             - REQUIRED; incorporated into rules' names and descriptions.
* paths             - REQUIRED; identifies one or more paths (comma separated if more than one).
                      If a path is a directory, rules are generated for the existing files in that directory.
                      If a path is to a file, a rule is generated for that file.
* noRecurse         - OPTIONAL; if specified, rules are generated only for the files in the specified directory or directories.
                      Otherwise, rules are also generated for files in subdirectories of the specified directory or directories.
* enforceMinVersion - OPTIONAL; if specified, generated publisher rules enforce a minimum file version based on the file versions of the observed files.
                      Otherwise, the generated rules do not enforce a minimum file version.

Examples of valid hash tables:

    # Search one directory and its subdirectories for files to generate rules for. Don't include file version in generated publisher rules.
    @{
    label = "OneDrive";
    paths = "$env:LOCALAPPDATA\Microsoft\OneDrive";
    enforceMinVersion = $false
    }


    # Search two separate directory structures for files to generate rules for, plus one explicitly-identified file.
    @{
    label = "ContosoIT";
    paths = "$env:LOCALAPPDATA\Programs\MyContosoIT\Helper",
           "C:\ProgramData\COntosoIT\ContosoIT System Health Client",
           "$env:LOCALAPPDATA\TEMP\CORPSEC\ITGSECLOGONGPEXEC.EXE"
    }

    # Generate rules for three distinct files; do not recurse subdirectories looking for additional matches.
    @{
    label = "Custom backup scripts";
    paths = "C:\Backups\MyBackup.vbs",
            "C:\Backups\MyPersonalBackup.vbs",
            "C:\Backups\Exports\RegExport.1.cmd";
    noRecurse = $true
    }
#>

@{
label = "OneDrive";
paths = "$env:LOCALAPPDATA\Microsoft\OneDrive";
enforceMinVersion = $false;
customUserOrGroupSid = "S-1-5-32-547"
}



