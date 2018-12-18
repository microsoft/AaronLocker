<#
.SYNOPSIS
Revert local AppLocker policy to "not configured".
Requires administrative rights.
#>

####################################################################################################
# Ensure the AppLocker assembly is loaded. (Scripts sometimes run into TypeNotFound errors if not.)
####################################################################################################
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")


Set-AppLockerPolicy -PolicyObject ([Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::new())