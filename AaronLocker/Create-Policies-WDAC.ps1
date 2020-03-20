<#
.SYNOPSIS
IMPORTANT: Intended to be dot-sourced into other scripts, and not run directly.

Script used by Create-Policies.ps1 to build WDAC-specific "audit" and "enforce" rules to mitigate against users running unauthorized software, customizable through simple text files. Writes results to the Outputs subdirectory.

TODO: Find and remove redundant rules. Report stripped rules to a separate log file.

.DESCRIPTION
Create-Policies-WDAC.ps1 is called by Create-Policies.ps1 to generate comprehensive "audit" and "enforce" WDAC rules to restrict non-admin code execution to "authorized" softwaretories.

#>

####################################################################################################
# Initialize XML template variables used only by this script (see Config.ps1 for global variables used by AaronLocker)
####################################################################################################
[xml]$WDACBaseXML = Get-Content -Path $env:windir"\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"

$WDACAllowRulesXMLFile = ([System.IO.Path]::Combine($mergeRulesDynamicDir, $WDACrulesFileBase + "AllowRules.xml"))
[xml]$WDACTemplateXML = Get-Content -Path $env:windir"\schemas\CodeIntegrity\ExamplePolicies\DenyAllAudit.xml"
$nsuri = "urn:schemas-microsoft-com:sipolicy"
$nsBase = new-object Xml.XmlNamespaceManager $WDACTemplateXML.NameTable
$nsBase.AddNamespace("si", $nsuri)

[xml]$WDACDenyBaseXML = Get-Content -Path $env:windir"\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml"


####################################################################################################
# Build WDAC Allow rules policy (Deny rules will be in separate policy created later in this script)
####################################################################################################

# Delete previous set of dynamically-generated rules first
Remove-Item ([System.IO.Path]::Combine($mergeRulesDynamicDir, "WDAC*.xml"))

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
$FileRulesNode = $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:FileRules",$nsBase)
$SignersNode = $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:Signers",$nsBase)
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
                    if ($curTypeId -ne "FileAttrib") {$WDACAllowRules[-$i].Id = $WDACAllowRules[-$i].Id+"_"+$label.Replace(" ","_")}
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
                    $newFileAttrib = $WDACTemplateXML.CreateElement("FileAttrib",$nsuri)
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
                $newSigner = $WDACTemplateXML.CreateElement("Signer",$nsuri)
                $SignerId = "ID_SIGNER_S_"+$CustomRuleCount+"_"+$label.Replace(" ","_")

                $newSigner.SetAttribute("ID",$SignerId)
                $newSigner.SetAttribute("Name",$IssuerName)

                $CertRootNode = $WDACTemplateXML.CreateElement("CertRoot",$nsuri) 
                $CertRootNode.SetAttribute("Type","TBS")
                $CertRootNode.SetAttribute("Value",$IssuerTBSHash)

                $newSigner.AppendChild($CertRootNode)

                # Add Publisher if present
                if ($null -ne $publisher) 
                {
                    $PubNode = $WDACTemplateXML.CreateElement("CertPublisher",$nsuri)
                    $PubNode.SetAttribute("Value",$publisher)
                    $newSigner.AppendChild($PubNode)
                }

                # Add reference to FileAttrib rule if any of ProductName, FileName, or FileVersion is present
                if ($null -ne $FileAttribId)
                {
                    $FileAttribRefNode = $WDACTemplateXML.CreateElement("FileAttribRef",$nsuri)
                    $FileAttribRefNode.SetAttribute("RuleId",$FileAttribId)
                    $newSigner.AppendChild($FileAttribRefNode)
                }
                $SignersNode.AppendChild($newSigner)

                # Add AllowedSigners node under signing scenario 12 (user mode) if it doesn't exist
                if ($WDACTemplateXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:AllowedSigners",$nsBase) -eq $null)
                {
                    $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners",$nsBase).AppendChild($WDACTemplateXML.CreateElement("AllowedSigners",$nsuri))
                }

                # Add signer rule to User mode rules
                $UserModeSigners = $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:AllowedSigners",$nsBase)
                $AllowedSignerRuleNode = $WDACTemplateXML.CreateElement("AllowedSigner",$nsuri)
                $AllowedSignerRuleNode.SetAttribute("SignerId",$SignerId)
                $UserModeSigners.AppendChild($AllowedSignerRuleNode)

                # Add signer rule to CISigners rules
                $CISigners = $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:CiSigners",$nsBase)
                $CISignersRuleNode = $WDACTemplateXML.CreateElement("CiSigner",$nsuri)
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

    $newFileAllow = $WDACTemplateXML.CreateElement("Allow",$nsuri)
    $newFileAllow.SetAttribute("ID",$FileHashAllowId)
    $newFileAllow.SetAttribute("FriendlyName",$HashRuleName)
    $newFileAllow.SetAttribute("Hash", $HashValue)

    $FileRulesNode.AppendChild($newFileAllow)

    # Add FileRulesRef node under signing scenario 12 (user mode) if it doesn't exist
    if ($WDACTemplateXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:FileRulesRef",$nsBase) -eq $null)
    {
        $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners",$nsBase).AppendChild($WDACTemplateXML.CreateElement("FileRulesRef",$nsuri))
    }

    # Add FileAllow rule to User mode rules
    $UserModeFileRules = $WDACTemplateXML.DocumentElement.SelectSingleNode("//si:SigningScenario[@Value = '12']/si:ProductSigners/si:FileRulesRef",$nsBase)
    $AllowedFileRuleRefNode = $WDACTemplateXML.CreateElement("FileRuleRef",$nsuri)
    $AllowedFileRuleRefNode.SetAttribute("RuleId",$FileHashAllowId)
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
                    if ($curTypeId -ne "FileAttrib") {$WDACAllowRules[-$i].Id = $WDACAllowRules[-$i].Id+"_"+$label.Replace(" ","_")}
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
SaveXmlDocAsUnicode -xmlDoc $WDACTemplateXML -xmlFilename $WDACAllowRulesXMLFile
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


<####################################################################################################
# Tag with timestamp into the rule set
####################################################################################################

# Define an AppLocker policy to fill containing a bogus hash rule containing timestamp information; hash contains timestamp, as does name and description
$timestampXml = [xml]@"
    <AppLockerPolicy Version="1">
      <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
        <FileHashRule Name="Rule set created $strRuleDocTimestamp" Description="Never-applicable rule to document that this AppLocker rule set was created via AaronLocker at $strRuleDocTimestamp" UserOrGroupSid="S-1-3-0" Action="Deny" Id="456bd77c-5528-4a93-8ab8-51c6b950c541">
            <Conditions>
              <FileHashCondition>
                <FileHash Type="SHA256" Data="0x00000000000000000000000000000000000000000000000000$strTimestampForHashRule" SourceFileName="DateTimeInfo" SourceFileLength="1"/>
              </FileHashCondition>
            </Conditions>
        </FileHashRule>
      </RuleCollection>
      <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
      <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
      <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    </AppLockerPolicy>
"@

$timestampFile = [System.IO.Path]::Combine($mergeRulesDynamicDir, "TimestampData.xml")
# Save XML as Unicode
SaveXmlDocAsUnicode -xmlDoc $timestampXml -xmlFilename $timestampFile

####################################################################################################
# Merging custom rules
####################################################################################################

# --------------------------------------------------------------------------------
# Load the XML document with modifications into an AppLockerPolicy object
$masterPolicy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::FromXml($xDocument.OuterXml)

Write-Host "Loading custom rule sets..." -ForegroundColor Cyan
# Merge any and all policy files found in the MergeRules directories, typically for authorized files in writable directories.
# Some may have been created in the previous step; others might have been dropped in from other sources.
Get-ChildItem $mergeRulesDynamicDir\*.xml, $mergeRulesStaticDir\*.xml | foreach {
    $policyFileToMerge = $_
    Write-Host ("`tMerging " + $_.Directory.Name + "\" + $_.Name) -ForegroundColor Cyan
    $policyToMerge = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::Load($policyFileToMerge)
    $masterPolicy.Merge($policyToMerge)
}

# Delete the timestamp file so that it never gets copied accidentally to the MergeRules-Static directory
Remove-Item $timestampFile

#TODO: Optimize rules in rule collections here - combine/remove redundant/overlapping rules

####################################################################################################
# Generate final outputs
####################################################################################################

# Generate two versions of the rules file: one with rules enforced, and one with auditing only.

Write-Host "Creating final rule outputs..." -ForegroundColor Cyan

# Generate the Enforced version
foreach( $ruleCollection in $masterPolicy.RuleCollections)
{
    $ruleCollection.EnforcementMode = "Enabled"
}
SaveAppLockerPolicyAsUnicodeXml -ALPolicy $masterPolicy -xmlFilename $rulesFileEnforceNew

# Generate the AuditOnly version
foreach( $ruleCollection in $masterPolicy.RuleCollections)
{
    $ruleCollection.EnforcementMode = "AuditOnly"
}
SaveAppLockerPolicyAsUnicodeXml -ALPolicy $masterPolicy -xmlFilename $rulesFileAuditNew

if ($Excel)
{
    & $ps1_ExportPolicyToExcel -AppLockerXML $rulesFileEnforceNew -SaveWorkbook
    & $ps1_ExportPolicyToExcel -AppLockerXML $rulesFileAuditNew -SaveWorkbook
}

# --------------------------------------------------------------------------------
#>