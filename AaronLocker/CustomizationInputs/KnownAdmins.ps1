<#
.SYNOPSIS
Outputs a list of known administrative users or groups that should be ignored when scanning for "user-writable" directories.

.DESCRIPTION
Outputs a list of zero or more administrative users or groups that Enum-WritableDirs.ps1 does not know about (e.g., custom domain or local groups or users), one to a line.

The script framework scans for "user-writable" directories, looking for "write" permissions and ignoring permissions granted
to "known administrative" users and groups. The framework might fail to recognize custom domain groups and (in some cases)
local user accounts as administrative. This script enables adding those entities to the list of known administrative users/groups.
Output one entity name or SID per line.

Examples where this might be needed:
* Custom domain groups that have administrative rights.
* On Azure Active Directory joined systems, enumeration of BUILTIN\Administrators might not work correctly - might need to enumerate administrative accounts explicitly.

Examples:

    "DESKTOP-7TPCJ7J\renamedAdmin"
    "CONTOSO\SCCM-Admins"

#>

