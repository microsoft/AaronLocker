<#
.SYNOPSIS
IMPORTANT: Intended to be dot-sourced into other scripts, and not run directly.

Script used by Create-Policies.ps1 to build WDAC-specific "audit" and "enforce" rules to mitigate against users running unauthorized software, customizable through simple text files. Writes results to the Outputs subdirectory.

TODO: Find and remove redundant rules. Report stripped rules to a separate log file.

.DESCRIPTION
Create-Policies-WDAC.ps1 is called by Create-Policies.ps1 to generate comprehensive "audit" and "enforce" WDAC rules to restrict non-admin code execution to "authorized" softwaretories.

#>

####################################################################################################
# Initialize variables used only by this script (see Config.ps1 for global variables used by AaronLocker)
# It may be counterintuitive, but the Deny base policy used is the Windows template for "Allow All" and the Allow base policy
# used is the Windows template for "Deny All". This is by design for these scripts.
####################################################################################################
$WDACBaseXMLFile = $env:windir+"\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
$WDACDenyBaseXMLFile = $env:windir+"\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml"
$WDACAllowBaseXMLFile = $env:windir+"\schemas\CodeIntegrity\ExamplePolicies\DenyAllAudit.xml"

$WDACAllowRulesXMLFile = ([System.IO.Path]::Combine($mergeRulesDynamicDir, $WDACrulesFileBase + "AllowRules.xml"))
$WDACBlockPolicyXMLFile = [System.IO.Path]::Combine($mergeRulesDynamicDir, $WDACrulesFileBase + "ExeBlocklist.xml")

# Delete previous set of dynamically-generated rules first
Remove-Item ([System.IO.Path]::Combine($mergeRulesDynamicDir, $WDACrulesFileBase+"*.xml"))

####################################################################################################
# Build WDAC Allow rules policy (Deny rules will be in separate policy created later in this script)
####################################################################################################
[xml]$WDACAllowBaseXML = Get-Content -Path $WDACAllowBaseXMLFile
$nsuri = "urn:schemas-microsoft-com:sipolicy"
$nsBase = new-object Xml.XmlNamespaceManager $WDACAllowBaseXML.NameTable
$nsBase.AddNamespace("si", $nsuri)

<#
####################################################################################################
# TODO (one day When WDAC adds exception support, allow AppLocker-style rules)
# Note that WDAC, by-default, enforces a run-time check that the current directory does not grant write permissions to non-standard admin users.
# However, the runtime check by WDAC is not a security feature in Windows and won't prevent a malicious user from altering the ACLs to make a previously
# user-writable path pass the admin-only check after the fact. 
####################################################################################################
# Process exceptions for user-writable paths when a custom admin exists

# Then implement logic similar to AppLocker for the rest to build exceptions for user-writable paths. The following is the current relevant code from AppLocker rule sections:
#>

# --------------------------------------------------------------------------------
# Build WDAC allow rules starting with base Windows works example policy
# Add Windir, PF, and PFx86 to $PathsToAllow then create allow rule policy
# WDAC does not work with system variables for Program Files, so rules will be based on the values for the machine where the scan runs.
# --------------------------------------------------------------------------------
$WDACPathsToAllow = @($PathsToAllow)
$WDACPathsToAllow += "%windir%\*"
$WDACPathsToAllow += $env:ProgramFiles+"\*"
if ($null -ne ${env:ProgramFiles(x86)}) {$WDACPathsToAllow += (${env:ProgramFiles(x86)}+"\*")}

$WDACPathsToAllow | foreach {
    $pathToAllow = $_
    $WDACAllowRules += & New-CIPolicyRule -FilePathRule $pathToAllow -AllowFileNameFallbacks
}

# --------------------------------------------------------------------------------
# Create rules for trusted publishers
# --------------------------------------------------------------------------------
Write-Host "Creating rules for trusted publishers..." -ForegroundColor Cyan

# Run the script that produces the signer information to process. Should come in as a sequence of hashtables.
# Each hashtable must have a label, and either an exemplar or a publisher.
$FileRulesNode = $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:FileRules",$nsBase)
$SignersNode = $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:Signers",$nsBase)
$CustomRuleCount = 0
$WDACsignersToBuildRulesFor = (& $ps1_TrustedSignersWDAC)
$WDACsignersToBuildRulesFor | foreach {
    $label = $_.label
    if ($label -eq $null)
    {
        # Each hashtable must have a label.
        Write-Warning -Message ("Invalid syntax in $ps1_TrustedSignersWDAC. No `"label`" specified.")
    }
    else
    {
        $IssuerName = $IssuerTBSHash = $publisher = $product = $filename = $fileVersion = $exemplarFile = ""
        $level = $_.level
        # Exemplar is a file whose signature/signed attributes match what we want to trust. If the hashtable specifies "useProduct" = $true,
        # the WDAC rule allows anything signed by that publisher with the same ProductName.
        if ($_.exemplar)
        {
            # Get count of $WDACAllowRules before adding new exemplar rule(s)
            $CurRuleCount = $WDACAllowRules.Count

            # Generate new rules from exemplar
            $exemplarFile = $_.exemplar
            if ((Test-Path($exemplarFile)))
            {
                if ($_.useProduct) 
                {
                    $SpecificFileNameLevel = "ProductName"
                    if (($_.level -eq $null) -or ($_.level -notin "FilePublisher","FileName"))
                    {
                        Write-Warning -Message ("useProduct can only be used when level is 'FilePublisher' or 'FileName'. Setting level to 'FilePublisher'");
                        $level = "FilePublisher"
                    }
                }
                else 
                {
                    $SpecificFileNameLevel = "None"
                }

                if ($_.level -eq $null)            {
                    $level = "Publisher"
                }
                Write-Host "Creating rules for $exemplarFile at Level $level and SpecificFileNameLevel $SpecificFileNameLevel..." -ForegroundColor Cyan

                $WDACAllowRules += & New-CIPolicyRule -DriverFilePath $exemplarFile -Level $level -SpecificFileNameLevel $SpecificFileNameLevel
                # Determine how many new allow rules were added. This will be used to set Name to match the label and/or add ProductName restriction.
                $NumRulesAdded = ($WDACAllowRules.Count - $CurRuleCount)

                # Set the name for each added rule to the $label specified 
                $i=1
                While ($i -le $NumRulesAdded)
                {
                    $curTypeId = $WDACAllowRules[-$i].TypeId 
                    if ($curTypeId -ne "FileAttrib") {$WDACAllowRules[-$i].Id = $WDACAllowRules[-$i].Id+"_"+$label.ToUpper().Replace(" ","_")}
                    $i++
                }
            }
            else
            {
                Write-Warning -Message ("Exemplar file not found at $exemplarFile. Skipping...");
            }
        }
        else
        {
            # Otherwise, the hashtable must specify the exact IssuerName and IssuerTBSHash to trust (and optionally PublisherName, ProductName, FileName, FileVersion).
            $IssuerName = $_.IssuerName
            $IssuerTBSHash = $_.IssuerTBSHash
            $publisher = $_.PublisherName
            $product = $_.ProductName
            $filename = $_.FileName
            $fileVersion = $_.FileVersion
            if (($null -ne $IssuerName) -and ($null -ne $IssuerTBSHash))
            {
                $CustomRuleCount = $CustomRuleCount+1
                $FileAttribId = $null
                # --------------------------------------------------------------------------------
                # Add a new FileAttrib if any of ProductName, FileName, or FileVersion is present
                if (($null -ne $product) -or ($null -ne $filename) -or ($null -ne $fileVersion))
                {
                    $newFileAttrib = $WDACAllowBaseXML.CreateElement("FileAttrib",$nsuri)
                    $FileAttribId = "ID_FILEATTRIB_F_"+$CustomRuleCount
                    $newFileAttrib.SetAttribute("ID",$FileAttribId)
                    $newFileAttrib.SetAttribute("FriendlyName",$label)
                    if ($null -ne $product) {$newFileAttrib.SetAttribute("ProductName",$product)}
                    if ($null -ne $filename) {$newFileAttrib.SetAttribute("FileName",$filename)}
                    if ($null -ne $fileVersion) {$newFileAttrib.SetAttribute("MinimumFileVersion",$fileVersion)}

                    $FileRulesNode.AppendChild($newFileAttrib)
                }

                # --------------------------------------------------------------------------------
                # Build out the XML for the new Signer rule starting with the PCA certificate info
                $newSigner = $WDACAllowBaseXML.CreateElement("Signer",$nsuri)
                $SignerId = "ID_SIGNER_S_"+$CustomRuleCount+"_"+$label.ToUpper().Replace(" ","_")

                $newSigner.SetAttribute("ID",$SignerId)
                $newSigner.SetAttribute("Name",$IssuerName)

                $CertRootNode = $WDACAllowBaseXML.CreateElement("CertRoot",$nsuri) 
                $CertRootNode.SetAttribute("Type","TBS")
                $CertRootNode.SetAttribute("Value",$IssuerTBSHash)

                $newSigner.AppendChild($CertRootNode)

                # Add Publisher if present
                if ($null -ne $publisher) 
                {
                    $PubNode = $WDACAllowBaseXML.CreateElement("CertPublisher",$nsuri)
                    $PubNode.SetAttribute("Value",$publisher)
                    $newSigner.AppendChild($PubNode)
                }

                # Add reference to FileAttrib rule if any of ProductName, FileName, or FileVersion is present
                if ($null -ne $FileAttribId)
                {
                    $FileAttribRefNode = $WDACAllowBaseXML.CreateElement("FileAttribRef",$nsuri)
                    $FileAttribRefNode.SetAttribute("RuleID",$FileAttribId)
                    $newSigner.AppendChild($FileAttribRefNode)
                }
                $SignersNode.AppendChild($newSigner)

                # Add AllowedSigners node under signing scenario 12 (user mode) if it doesn't exist
                if ($WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:AllowedSigners",$nsBase) -eq $null)
                {
                    $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners",$nsBase).AppendChild($WDACAllowBaseXML.CreateElement("AllowedSigners",$nsuri))
                }

                # Add signer rule to User mode rules
                $UserModeSigners = $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:AllowedSigners",$nsBase)
                $AllowedSignerRuleNode = $WDACAllowBaseXML.CreateElement("AllowedSigner",$nsuri)
                $AllowedSignerRuleNode.SetAttribute("SignerId",$SignerId)
                $UserModeSigners.AppendChild($AllowedSignerRuleNode)

                # Add signer rule to CISigners rules
                $CISigners = $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:CiSigners",$nsBase)
                $CISignersRuleNode = $WDACAllowBaseXML.CreateElement("CiSigner",$nsuri)
                $CISignersRuleNode.SetAttribute("SignerId",$SignerId)
                $CISigners.AppendChild($CISignersRuleNode)
            }
            else
            {
                # Object isn't a hashtable, or doesn't have either exemplar or PCACertificate information.
                Write-Warning -Message ("Invalid syntax in $ps1_TrustedSignersWDAC")
            }
        }
    }
}

# --------------------------------------------------------------------------------
# Create custom hash rules
# --------------------------------------------------------------------------------
Write-Host "Creating extra hash rules ..." -ForegroundColor Cyan

$hashRuleData | foreach {
    $CustomRuleCount = $CustomRuleCount+1

    $HashRuleName = $_.RuleName
    $HashValue = $_.HashVal.Substring(2)
    $FileName = $_.FileName
    $FileHashAllowId = "ID_ALLOW_A_"+$CustomRuleCount+$FileName.Replace(" ","_")

    $newFileAllow = $WDACAllowBaseXML.CreateElement("Allow",$nsuri)
    $newFileAllow.SetAttribute("ID",$FileHashAllowId)
    $newFileAllow.SetAttribute("FriendlyName",$HashRuleName)
    $newFileAllow.SetAttribute("Hash", $HashValue)

    $FileRulesNode.AppendChild($newFileAllow)

    # Add FileRulesRef node under signing scenario 12 (user mode) if it doesn't exist
    if ($WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:FileRulesRef",$nsBase) -eq $null)
    {
        $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners",$nsBase).AppendChild($WDACAllowBaseXML.CreateElement("FileRulesRef",$nsuri))
    }

    # Add FileAllow rule to User mode rules
    $UserModeFileRules = $WDACAllowBaseXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:FileRulesRef",$nsBase)
    $AllowedFileRuleRefNode = $WDACAllowBaseXML.CreateElement("FileRuleRef",$nsuri)
    $AllowedFileRuleRefNode.SetAttribute("RuleID",$FileHashAllowId)
    $UserModeFileRules.AppendChild($AllowedFileRuleRefNode)
}

# --------------------------------------------------------------------------------
# Rules for files in user-writable directories
# --------------------------------------------------------------------------------
# Build rules for files in writable directories identified in the "unsafe paths to build rules for" script.
# Uses BuildRulesForFilesInWritableDirectories.ps1.
# Writes results to the dynamic merge-rules directory, using the script-supplied labels as part of the file name.
# The files in the merge-rules directories will be merged into the main document later.
# (Doing this after the other files are created in the MergeRulesDynamicDir - file naming logic handles cases where
# file already exists from the other dynamically-generated files above, or if multiple items have the same label.
Write-Host "Creating rules for files in 'unsafe' paths..." -ForegroundColor Cyan

$UnsafePathsToBuildRulesFor | foreach {
    $label = $_.label
    if ($ForUser)
    {
        $paths = RenamePaths -paths $_.paths -forUsername $ForUser
    }
    else
    {
        $paths = $_.paths
    }
    switch ($_.pubruleGranularity)
    {
        "pubOnly" 
        { 
            $level = "Publisher"
            $SpecificFileNameLevel = "None"
            $Fallback = "FilePublisher,FileName,Hash"
        }
        "pubProduct"
        {
            $level = "FilePublisher"
            $SpecificFileNameLevel = "ProductName"
            $Fallback = "FilePublisher,FileName,Hash"
        }
        "pubProductBinary"
        {
            $level = "FilePublisher"
            $SpecificFileNameLevel = "OriginalFileName"
            $Fallback = "FileName,Hash"
        }
        "pubProdBinVer"
        {
            $level = "FilePublisher"
            $SpecificFileNameLevel = "OriginalFileName"
            $Fallback = "FileName,Hash"
        }
        # This catch-all here in case the parameter ValidateSet attribute changes and this block doesn't...
        default
        {
            Write-Error -Category InvalidArgument -Message "`nINVALID PubRuleGranularity: $PubRuleGranularity"
            return
        }
    }

    # Get count of $WDACAllowRules before adding new "unsafe" rule(s)
    $CurRuleCount = $WDACAllowRules.Count

    # Generate new rules for each specified path
    foreach ($CurPath in $paths)
    {
        # E.g., in case of blank lines in input file
        $CurPath = $CurPath.Trim()
        if ($CurPath.Length -gt 0)
        {
            if (Test-Path $CurPath)
            {
                Write-Host "Generating rules for specified path: $CurPath..." -ForegroundColor Cyan
                # Determine whether directory or file and run new-cipolicyrule with the appropriate switches for path or single file
                $PathInfo = Get-Item $CurPath -Force
                if ($PathInfo -is [System.IO.DirectoryInfo])
                {
                    $DriverFiles = Get-SystemDriver -ScanPath $CurPath -UserPEs
                    if ($DriverFiles.Count > 0) 
                    {
                        $WDACAllowRules += & New-CIPolicyRule -DriverFiles $DriverFiles -Level $level -Fallback $Fallback -SpecificFileNameLevel $SpecificFileNameLevel
                    }
                }
                else 
                {
                    $WDACAllowRules += & New-CIPolicyRule -DriverFilePath $CurPath -Level $level -Fallback $Fallback -SpecificFileNameLevel $SpecificFileNameLevel
                }

                # Determine how many new allow rules were added. This will be used to set Name to match the label and/or add ProductName restriction.
                $NumRulesAdded = ($WDACAllowRules.Count - $CurRuleCount)

                # Set the name for each added rule to the $label specified 
                $i=1
                While ($i -le $NumRulesAdded)
                {
                    $curTypeId = $WDACAllowRules[-$i].TypeId 
                    if ($curTypeId -ne "FileAttrib") {$WDACAllowRules[-$i].Id = $WDACAllowRules[-$i].Id+"_"+$label.ToUpper().Replace(" ","_")}
                    $i++
                }
            }
            else
            {
                Write-Warning -Message ("Specified path not found: $CurPath. Skipping...");
            }
        }
    }
}

Write-Host "Saving policy XML for custom publisher and hash rules..." -ForegroundColor Cyan
# Save XML as Unicode
SaveXmlDocAsUnicode -xmlDoc $WDACAllowBaseXML -xmlFilename $WDACAllowRulesXMLFile
Merge-CIPolicy -OutputFilePath $WDACAllowRulesXMLFile -PolicyPaths $WDACAllowRulesXMLFile -Rules $WDACAllowRules


###################################################################################################
# Create block policy from Exe files to blacklist if needed. Merge the deny rules with the allow all example policy.
####################################################################################################
if ( $Rescan -or !(Test-Path($WDACBlockPolicyXMLFile) ) )
{
    Write-Host "Processing EXE files to block..." -ForegroundColor Cyan
    # Create a hash collection for publisher information. Key on publisher name, product name, and binary name.
    # Add to collection if equivalent is not already in the collection.
    $WDACExeFilesToBlock = @()
    $WDACExeFilesToBlock += $exeFilesToBlackList
	$WDACBlockRules = & New-CIPolicyRule  -DriverFilePath $WDACExeFilesToBlock -Level FilePublisher -Fallback FileName, Hash, FilePath -Deny
    New-CIPolicy -Rules $WDACBlockRules -FilePath $WDACBlockPolicyXMLFile -UserPEs -MultiplePolicyFormat
}


####################################################################################################
# Build final policies by merging dynamic and static (if any) custom rules into WDAC template policy files
####################################################################################################
# Generate two versions of the Allow rules file and two versions of the Deny rules file: one with rules enforced, and one with auditing only for each.
foreach ($CurPolicyType in "Allow","Deny")
{
    if ($CurPolicyType = "Allow")
    {
        $CurBaseXMLFile = $WDACBaseXMLFile
        $CurAuditPolicyXMLFile = $WDACrulesFileAuditNew
        $CurEnforcedPolicyXMLFile = $WDACrulesFileEnforceNew
        $PreviousPolicyXMLFile = WDACRulesFileAuditLatest
        $Exclusion = "*Deny*"
    }
    else
    {
        $CurBaseXMLFile = $WDACDenyBaseXMLFile
        $CurAuditPolicyXMLFile = $WDACDenyrulesFileAuditNew
        $CurEnforcedPolicyXMLFile = $WDACDenyrulesFileEnforceNew
        $PreviousPolicyXMLFile = WDACDenyRulesFileAuditLatest
        $Exclusion = "*Allow*"
    }

    # Get the Policy ID and version from the previous WDAC policy (if it exists). Otherwise, set defaults.
    if ($PreviousPolicyXMLFile -ne $null)
    {
        [xml]$PreviousPolicyXML = Get-Content -Path $PreviousPolicyXMLFile
        $PreviousPolicyVersion = [version]$PreviousPolicyXML.SiPolicy.VersionEx
        $PolicyVersion = [version]::New($PreviousPolicyVersion.Major,$PreviousPolicyVersion.Minor,$PreviousPolicyVersion.Build,$PreviousPolicyVersion.Revision+1)
        [string]$PolicyID = $PreviousPolicyXML.SiPolicy.PolicyID
    }
    else
    {
        $PolicyVersion = "1.0.0.0"
        $PolicyID = $null
    }

    $PolicyName = "WDAC AaronLocker "+ $CurPolicyType +" list - Audit"
    
    # Copy Base policy template to Outputs folder and rename
    cp $CurBaseXMLFile $CurAuditPolicyXMLFile

    Write-Host "Merging custom rule sets into new policy file..." -ForegroundColor Cyan
    # Merge any and all policy files found in the MergeRules directories, typically for authorized files in writable directories.
    # Some may have been created in the previous step; others might have been dropped in from other sources.
    Get-ChildItem $mergeRulesDynamicDir\$WDACrulesFileBase*.xml, $mergeRulesStaticDir\$WDACrulesFileBase*.xml -Exclude $Exclusion | foreach {
        $policyFileToMerge = $_
        Write-Host ("`tMerging " + $_.Directory.Name + "\" + $_.Name) -ForegroundColor Cyan
        Merge-CIPolicy -OutputFilePath $CurAuditPolicyXMLFile -PolicyPaths $CurAuditPolicyXMLFile,$policyFileToMerge
    }

    # Set policy options for audit policy
    Set-RuleOption -FilePath $CurAuditPolicyXMLFile -Option 12 # Required:Enforce Store Applications
    if ($WDACTrustManagedInstallers) {Set-RuleOption -FilePath $CurAuditPolicyXMLFile -Option 13} # Enabled:Managed Installer
    if ($WDACTrustISG) {Set-RuleOption -FilePath $CurAuditPolicyXMLFile -Option 14} # Enabled:Intelligent Security Graph Authorization
    if ($knownAdmins.Count > 0) {Set-RuleOption -FilePath $CurAuditPolicyXMLFile -Option 18} # Disabled:Runtime FilePath Rule Protection

    # Set policy name, version, and timestamp for the new policy file
    Set-CIPolicyIdInfo -FilePath $CurAuditPolicyXMLFile -PolicyName $PolicyName 
    Set-CIPolicyVersion -FilePath $CurAuditPolicyXMLFile -Version $PolicyVersion
    Set-CIPolicySetting -FilePath $CurAuditPolicyXMLFile -Provider "PolicyInfo" -Key "Information" -ValueName "TimeStamp" -ValueType String -Value $strRuleDocTimestamp

    #Set new policy ID to previous policy ID (if exists) or generate new ID
    if ($PolicyID -ne $null)
    {
        [xml]$CurAuditPolicyXML = Get-Content -Path $CurAuditPolicyXMLFile
        $CurAuditPolicyXML.SiPolicy.BasePolicyID = $PolicyID
        $CurAuditPolicyXML.SiPolicy.PolicyID = $PolicyID
        Write-Host "Saving $CurAuditPolicyXMLFile after setting PolicyID info from previous run..." -ForegroundColor Cyan
        # Save XML as Unicode
        SaveXmlDocAsUnicode -xmlDoc $CurAuditPolicyXML -xmlFilename $CurAuditPolicyXMLFile
    }
    else
    {
        Set-CIPolicyIdInfo -FilePath $CurAuditPolicyXMLFile -ResetPolicyID
    }

    # Copy Audit policy to enforced
    cp $CurAuditPolicyXMLFile $CurEnforcedPolicyXMLFile

    # Update policy name for enforced policy
    $PolicyName = "WDAC AaronLocker "+ $CurPolicyType +" list - Enforced"
    Set-CIPolicyIdInfo -FilePath $CurEnforcedPolicyXMLFile -PolicyName $PolicyName

    # Remove audit mode option from enforced policy 
    Set-RuleOption -FilePath $CurEnforcedPolicyXMLFile -Option 3 -Delete # Turn off audit mode
}

# --------------------------------------------------------------------------------
