<#
.SYNOPSIS
Sets the output encoding for the current session to Unicode, so that piped output retains Unicode encoding.

#>

$global:OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

