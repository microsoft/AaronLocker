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
$nsBase = new-object Xml.XmlNamespaceManager $WDACTemplateXML.NameTable
$nsBase.AddNamespace("si", "urn:schemas-microsoft-com:sipolicy")
[xml]$WDACDenyBaseXML = Get-Content -Path $env:windir"\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml"

####################################################################################################
# Build WDAC Allow rules policy (Deny rules will be in separate policy created later in this script)
####################################################################################################

# Delete previous set of dynamically-generated rules first
Remove-Item ([System.IO.Path]::Combine($mergeRulesDynamicDir, "WDAC*.xml"))

# --------------------------------------------------------------------------------
# Build WDAC allow rules starting with base Windows works example policy
# Add Windir, PF, and PFx86 to $PathsToAllow then create allow rule policy
# WDAC does not work with system variables for Program Files, so rules will be based on the values for the machine where the scan runs.
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
Write-Host "Creating rules for trusted publishers..." -ForegroundColor Cyan
# $node=$WDACBaseXML.SelectSingleNode("//si:Signers",$nsBase)

# Run the script that produces the signer information to process. Should come in as a sequence of hashtables.
# Each hashtable must have a label, and either an exemplar or a publisher.
# $fprRulesEmpty: Don't generate TrustedSigners.xml if it doesn't have any rules.
$fprRulesEmpty = $true
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
        $good = $false
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
                $good = $true
            }
            else
            {
                # Object isn't a hashtable, or doesn't have either exemplar or PCACertificate information.
                Write-Warning -Message ("Invalid syntax in $ps1_TrustedSignersWDAC")
            }

<#
            if ($good)
            {
                $fprRulesNotEmpty = $true

                # Duplicate the blank publisher rule, and populate it with information gathered.
                $fpr = $fprTemplate.Clone()
                $fpr.Conditions.FilePublisherCondition.PublisherName = $publisher

                $fpr.Name = "$label`: Signer rule for $publisher"
                if ($product.Length -gt 0)
                {
                    $fpr.Conditions.FilePublisherCondition.ProductName = $product
                    $fpr.Name = "$label`: Signer/product rule for $publisher/$product"
                    if ($filename.Length -gt 0)
                    {
                        $fpr.Conditions.FilePublisherCondition.BinaryName = $filename
                        $fpr.Name = "$label`: Signer/product/file rule for $publisher/$product/$filename"
                        if ($fileVersion.Length -gt 0)
                        {
                            $fpr.Conditions.FilePublisherCondition.BinaryVersionRange.LowSection = $fileVersion
                        }
                    }
                }
                if ($exemplarFile.Length -gt 0)
                {
                    $fpr.Description = "Information acquired from $exemplarFile"
                }
                else
                {
                    $fpr.Description = "Information acquired from $fname_TrustedSigners"
                }
                Write-Host ("`t" + $fpr.Name) -ForegroundColor Cyan

                if ($publisher.ToLower().Contains("microsoft") -and $product.Length -eq 0 -and ($ruleCollection.Length -eq 0 -or $ruleCollection -eq "Exe"))
                {
                    Write-Warning -Message ("Warning: Trusting all Microsoft-signed files is an overly-broad whitelisting strategy")
                }

                if ($ruleCollection)
                {
                    $node = $signerPolXml.SelectSingleNode("//RuleCollection[@Type='" + $ruleCollection + "']")
                    if ($node -eq $null)
                    {[
                        Write-Warning ("Couldn't find RuleCollection Type = " + $ruleCollection + " (RuleCollection is case-sensitive)")
                    }
                    else
                    {
                        $fpr.Id = [string]([GUID]::NewGuid().Guid)
                        $node.AppendChild($fpr) | Out-Null
                    }
                }
                else
                {
                    # Append a copy of the new publisher rule into each rule set with a different GUID in each.
                    $signerPolXml.SelectNodes("//RuleCollection") | foreach {
                        $fpr0 = $fpr.CloneNode($true)

                        $fpr0.Id = [string]([GUID]::NewGuid().Guid)
                        $_.AppendChild($fpr0) | Out-Null
                    }
                }
            }
#>
        }

    }
}

<# Don't generate the file if it doesn't contain any rules
if ($fprRulesNotEmpty)
{
    # Delete the blank publisher rule from the rule set.
    $fprTemplate.ParentNode.RemoveChild($fprTemplate) | Out-Null

    #$signerPolXml.OuterXml | clip
    $outfile = [System.IO.Path]::Combine($mergeRulesDynamicDir, "TrustedSigners.xml")
    # Save XML as Unicode
    SaveXmlDocAsUnicode -xmlDoc $signerPolXml -xmlFilename $outfile
}
#>

Write-Host "Creating policy from trusted publisher rules..." -ForegroundColor Cyan

New-CIPolicy -Rules $WDACAllowRules -FilePath $WDACAllowRulesXMLFile -UserPEs -MultiplePolicyFormat

<####################################################################################################
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


<#
$NewRuleXml = $node."
    <Signer ID='ID_SIGNER_S_33_Trust_the_publisher_of_GitHub_Desktop' Name='DigiCert SHA2 Assured ID Code Signing CA'>
      <CertRoot Type='TBS' Value='E767799478F64A34B3F53FF3BB9057FE1768F4AB178041B0DCC0FF1E210CBA65' />
      <CertPublisher Value='GitHub, Inc.' />
    </Signer>
"
####################################################################################################
# TODO (one day When WDAC adds exception support, allow AppLocker-style rules)
# Note that WDAC, by-default, enforces a run-time check that the current directory does not grant write permissions to non-standard admin users.
# However, the runtime check by WDAC is not a security feature in Windows and won't prevent a malicious user from altering the ACLs to make a previously
# user-writable path pass the admin-only check after the fact. 
####################################################################################################
# Process exceptions for user-writable paths when a custom admin exists

# Then implement logic similar to AppLocker for the rest to build exceptions for user-writable paths. The following is the current relevant code from AppLocker rule sections:


####################################################################################################
# Create custom hash rules
####################################################################################################
Write-Host "Creating extra hash rules ..." -ForegroundColor Cyan

# Define an empty AppLocker policy to fill, with a blank hash rule to use as a template.
$hashRuleXml = [xml]@"
    <AppLockerPolicy Version="1">
      <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
        <FileHashRule Id="" Name="" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
              <FileHashCondition>
                <FileHash Type="SHA256" Data="" SourceFileName="" SourceFileLength="0"/>
              </FileHashCondition>
            </Conditions>
        </FileHashRule>
      </RuleCollection>
      <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
      <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
      <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    </AppLockerPolicy>
"@
# Get the blank hash rule. It will be cloned to make the real hash rules.
$fhrTemplate = $hashRuleXml.DocumentElement.SelectNodes("//FileHashRule")[0]
# Remove the template rule from the main document
$fhrTemplate.ParentNode.RemoveChild($fhrTemplate) | Out-Null
# fhrRulesNotEmpty: Don't generate ExtraHashRules.xml if it doesn't have any rules.
$fhrRulesNotEmpty = $false

# Run the script that produces the hash information to process. Should come in as a sequence of hashtables.
# Each hashtable must have the following properties: 
# * RuleCollection (case-sensitive)
# * RuleName
# * RuleDesc
# * HashVal (must be SHA256 with "0x" and 64 hex digits)
# * FileName
$hashRuleData = (& $ps1_HashRuleData)

$hashRuleData | foreach {

    $fhr = $fhrTemplate.Clone()
    $fhr.Id = [string]([GUID]::NewGuid().Guid)
    $fhr.Name = $_.RuleName
    $fhr.Description = $_.RuleDesc
    $fhr.Conditions.FileHashCondition.FileHash.Data = $_.HashVal
    $fhr.Conditions.FileHashCondition.FileHash.SourceFileName = $_.FileName

    $node = $hashRuleXml.SelectSingleNode("//RuleCollection[@Type='" + $_.RuleCollection + "']")
    if ($node -eq $null)
    {
        Write-Warning ("Couldn't find RuleCollection Type = " + $_.RuleCollection + " (RuleCollection is case-sensitive)")
    }
    else
    {
        $node.AppendChild($fhr) | Out-Null
        $fhrRulesNotEmpty = $true
    }
}

# Don't generate the file if it doesn't contain any rules
if ($fhrRulesNotEmpty)
{
    $outfile = [System.IO.Path]::Combine($mergeRulesDynamicDir, "ExtraHashRules.xml")
    # Save XML as Unicode
    SaveXmlDocAsUnicode -xmlDoc $hashRuleXml -xmlFilename $outfile
}

####################################################################################################
# Rules for files in user-writable directories
####################################################################################################

# --------------------------------------------------------------------------------
# Helper function used to replace current username with another in paths.
function RenamePaths($paths, $forUsername)
{
    # Warning: if $forUsername is "Users" that will be a problem.
    $forUsername = "\" + $forUsername
    # Look for username bracketed by backslashes, or at end of the path.
    $CurrentName      = "\" + $env:USERNAME.ToLower() + "\"
    $CurrentNameFinal = "\" + $env:USERNAME.ToLower()

    $paths | ForEach-Object {
        $origTargetDir = $_
        # Temporarily remove trailing \* if present; can't GetFullPath with that.
        if ($origTargetDir.EndsWith("\*"))
        {
            $bAppend = "\*"
            $targetDir = $origTargetDir.Substring(0, $origTargetDir.Length - 2)
        }
        else
        {
            $bAppend = ""
            $targetDir = $origTargetDir
        }
        # GetFullPath in case the provided name is 8.3-shortened.
        $targetDir = [System.IO.Path]::GetFullPath($targetDir).ToLower()
        if ($targetDir.Contains($CurrentName) -or $targetDir.EndsWith($CurrentNameFinal))
        {
            $targetDir.Replace($CurrentNameFinal, $forUsername) + $bAppend
        }
        else
        {
            $origTargetDir
        }
    }
}

# --------------------------------------------------------------------------------
# Build rules for files in writable directories identified in the "unsafe paths to build rules for" script.
# Uses BuildRulesForFilesInWritableDirectories.ps1.
# Writes results to the dynamic merge-rules directory, using the script-supplied labels as part of the file name.
# The files in the merge-rules directories will be merged into the main document later.
# (Doing this after the other files are created in the MergeRulesDynamicDir - file naming logic handles cases where
# file already exists from the other dynamically-generated files above, or if multiple items have the same label.

if ( !(Test-Path($ps1_UnsafePathsToBuildRulesFor)) )
{
    $errmsg = "Script file not found: $ps1_UnsafePathsToBuildRulesFor`nNo new rules generated for files in writable directories."
    Write-Warning $errmsg
}
else
{
    Write-Host "Creating rules for files in writable directories..." -ForegroundColor Cyan
    $UnsafePathsToBuildRulesFor = (& $ps1_UnsafePathsToBuildRulesFor)
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
        $recurse = $true;
        if ($null -ne $_.noRecurse) { $recurse = !$_.noRecurse }
        $pubruleGranularity = "pubProductBinary"
        if ($null -ne $_.pubruleGranularity)
        {
            $pubruleGranularity = $_.pubruleGranularity
        }
        elseif ($null -ne $_.enforceMinVersion) # enforceMinVersion not considered if pubruleGranularity explicitly specified
        {
            if ($_.enforceMinVersion)
            {
                $pubruleGranularity = "pubProdBinVer";
            }
        }
        $outfilePub  = [System.IO.Path]::Combine($mergeRulesDynamicDir, $label + " Publisher Rules.xml")
        $outfileHash = [System.IO.Path]::Combine($mergeRulesDynamicDir, $label + " Hash Rules.xml")
        # If either already exists, create a pair of names that don't exist yet
        # (Just assume that when the rules file doesn't exist that the hash rules file doesn't either)
        $ixOutfile = [int]2
        while ((Test-Path($outfilePub)) -or (Test-Path($outfileHash)))
        {
            $outfilePub  = [System.IO.Path]::Combine($mergeRulesDynamicDir, $label + " (" + $ixOutfile.ToString() + ") Publisher Rules.xml")
            $outfileHash = [System.IO.Path]::Combine($mergeRulesDynamicDir, $label + " (" + $ixOutfile.ToString() + ") Hash Rules.xml")
            $ixOutfile++
        }
        Write-Host ("Scanning $label`:", $paths) -Separator "`n`t" -ForegroundColor Cyan
        & $ps1_BuildRulesForFilesInWritableDirectories -FileSystemPaths $paths -RecurseDirectories: $recurse -PubRuleGranularity $pubruleGranularity -RuleNamePrefix $label -OutputPubFileName $outfilePub -OutputHashFileName $outfileHash
    }
}

####################################################################################################
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
#>