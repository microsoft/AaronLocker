<#
.SYNOPSIS
Customizable script used by Create-Policies.ps1 that identifies user-writable paths containing files that need to be allowed to execute.

.DESCRIPTION
This script outputs a sequence of hashtables that identify user-writable files or directory paths containing content that users must be allowed to execute.
(The scripts favor publisher rules over hash rules.)
Each hashtable must include "label" and "paths" properties, with additional optional properties.
Hashtable properties:
* label              - REQUIRED; incorporated into rules' names and descriptions.
* paths              - REQUIRED; identifies one or more paths (comma separated if more than one).
                       If a path is a directory, rules are generated for the existing files in that directory.
                       If a path is to a file, a rule is generated for that file.
* pubruleGranularity - OPTIONAL; specifies granularity of publisher rules.
                       If specified, must be one of the following:
                         pubOnly - lowest granularity: Publisher rules specify publisher only
                         pubProduct - Publisher rules specify publisher and product
                         pubProductBinary - (default) Publisher rules specify publisher, product, and binary name
                         pubProdBinVer - highest granularity: Publisher rules specify publisher, product, binary name, and minimum version.
                       Microsoft-signed Windows and Visual Studio files are always handled at a minimum granularity of "pubProductBinary";
                       other Microsoft-signed files are handled at a minimum granularity of "pubProduct".
* JSHashRules        - OPTIONAL; if specified and set to $true, generates hash rules for unsigned .js files; otherwise, doesn't generate them.
* noRecurse          - OPTIONAL; if specified and set to $true, rules are generated only for the files in the specified directory or directories.
                       Otherwise, rules are also generated for files in subdirectories of the specified directory or directories.
* enforceMinVersion  - DEPRECATED and OPTIONAL. pubruleGranularity takes precedence if specified.
                         Otherwise, setting to $false equivalent to pubruleGranularity = pubProductBinary;
                         setting to $true equivalent to pubruleGranularity = pubProdBinVer.
                      
Examples of valid hash tables:

    # Search one directory and its subdirectories for files to generate rules for. 
    # Default granularity for publisher rules: create a separate rule for each file but allow any file version.
    @{
    label = "OneDrive";
    paths = "$env:LOCALAPPDATA\Microsoft\OneDrive";
    }

    # Search one directory and its subdirectories for files to generate rules for. 
    # Generated publisher rules contain only publisher and product names.
    # (Note that some Microsoft-signed files will also include binary name.)
    @{
    label = "OneDrive";
    paths = "$env:LOCALAPPDATA\Microsoft\OneDrive";
    pubruleGranularity = "pubProduct";
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
pubruleGranularity = "pubProduct";
}


