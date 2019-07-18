<#
.SYNOPSIS
IMPORTANT: Intended to be dot-sourced into other scripts, and not run directly.

Script used by Create-Policies.ps1 to build WDAC-specific "audit" and "enforce" rules to mitigate against users running unauthorized software, customizable through simple text files. Writes results to the Outputs subdirectory.

TODO: Find and remove redundant rules. Report stripped rules to a separate log file.

.DESCRIPTION
Create-Policies-WDAC.ps1 is called by Create-Policies.ps1 to generate comprehensive "audit" and "enforce" WDAC rules to restrict non-admin code execution to "authorized" softwaretories.

#>

<#
Write-Host "Rescan: "$Rescan -ForegroundColor Cyan
Write-Host "AppLockerOrWDAC: "$AppLockerOrWDAC -ForegroundColor Cyan
Write-Host "ProcessWDACLikeAppLocker: "$ProcessWDACLikeAppLocker -ForegroundColor Cyan
Write-Host "Custom admins: " -ForegroundColor Cyan
$knownAdmins
Write-Host "exeFilesToBlackList: " -ForegroundColor Cyan
$exeFilesToBlacklist
if ( $ProcessWDACLikeAppLocker -and ( ! ( (Test-Path($windirTxt)) -and (Test-Path($PfTxt)) -and (Test-Path($Pf86Txt)) ) ))
{
    $errMsg = "One or more of the following files is missing:`n" +
        "`t" + $windirTxt + "`n" +
        "`t" + $PfTxt + "`n" +
        "`t" + $Pf86Txt +"`n"
    Write-Error $errMsg
    return
}
#>

####################################################################################################
# Build WDAC rules starting with base "Windows works" example policy
####################################################################################################

# Delete previous set of dynamically-generated rules first
Remove-Item ([System.IO.Path]::Combine($mergeRulesDynamicDir, "WDAC*.xml"))

# --------------------------------------------------------------------------------
# Build WDAC rules starting with base Windows works example policy
$WDACBaseXML = ($env:windir+"\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml") 
$WDACPathsToAllowXML = ([System.IO.Path]::Combine($mergeRulesDynamicDir, $WDACrulesFileBase + "PathsToAllow.xml"))

####################################################################################################
# Add Windir, PF, and PFx86 to $PathsToAllow then create allow rule policy
####################################################################################################
# Due to WDAC bug with system variables for Program Files, workaround with prepended wildcard
$WDACPathsToAllow = @($PathsToAllow)
$WDACPathsToAllow += "%windir%\*","*\Program Files\*"
if ($null -ne ${env:ProgramFiles(x86)}) {$WDACPathsToAllow += "*\Program Files (x86)\*"}

$WDACPathsToAllow | foreach {
    # If path is an existing directory and doesn't have trailing "\*" appended, fix it so that it does.
    # If path is a file, don't append \*. If the path ends with \*, no need for further validation.
    # If it doesn't end with \* but Get-Item can't identify it as a file or a directory, write a warning and accept it as is.
    $pathToAllow = $_
    $WDACFilePathAllowRules += & New-CIPolicyRule -FilePathRule $pathToAllow -AllowFileNameFallbacks
}
New-CIPolicy -Rules $WDACFilePathAllowRules -FilePath $WDACPathsToAllowXML -UserPEs -MultiplePolicyFormat

# Process exceptions for user-writable paths when a custom admin exists
if ($ProcessWDACLikeAppLocker) 
{
    # Validate that scan-result files were created for user writable paths under windir and program files
    if ( ! ( (Test-Path($windirTxt)) -and (Test-Path($PfTxt)) -and (Test-Path($Pf86Txt)) ) )
    {
        $errMsg = "One or more of the following files is missing:`n" +
            "`t" + $windirTxt + "`n" +
            "`t" + $PfTxt + "`n" +
            "`t" + $Pf86Txt +"`n"
        Write-Error $errMsg
        return
    }
}

####################################################################################################
# Create block policy from Exe files to blacklist if needed
####################################################################################################
if ( $Rescan -or !(Test-Path($WDACBlockPolicyXML) ) )
{
    Write-Host "Processing EXE files to block..." -ForegroundColor Cyan
    # Create a hash collection for publisher information. Key on publisher name, product name, and binary name.
    # Add to collection if equivalent is not already in the collection.
    $WDACExeFilesToBlock = @()
    $WDACExeFilesToBlock += $exeFilesToBlackList
	$WDACBlockRules = & New-CIPolicyRule  -DriverFilePath $WDACExeFilesToBlock -Level FilePublisher -Fallback FileName, Hash, FilePath -Deny
    New-CIPolicy -Rules $WDACBlockRules -FilePath $WDACBlockPolicyXML -UserPEs -MultiplePolicyFormat
}


<#
####################################################################################################
# TODO (one day)
####################################################################################################

# --------------------------------------------------------------------------------
# Read the lists of user-writable directories with redundancies removed.
$Wr_raw_windir = (Get-Content $windirTxt)
$Wr_raw_PF     = (Get-Content $PfTxt)
$Wr_raw_PF86   = (Get-Content $Pf86Txt)

# --------------------------------------------------------------------------------
# Process names of directories, replacing hardcoded C:\, \Windows, etc., with AppLocker variables.
# Note that System32 and SysWOW64 map to the same variable names, as do the two ProgramFiles directories.
# Add trailing backslashes to the names (e.g., C:\Windows\System32\ ), so that if there happens to be
# a "C:\Windows\System32Extra" it won't match the System32 variable.
# Note that because of the trailing backslashes, if the top directories themselves are user-writable,
# they won't turn up in the list. That by itself would be a major problem, though.
$sSystem32 = "$env:windir\System32\".ToLower()
$sSysWow64 = "$env:windir\SysWOW64\".ToLower()
$sWindir   = "$env:windir\".ToLower()
$sPF86     = "${env:ProgramFiles(x86)}\".ToLower()
$sPF       = "$env:ProgramFiles\".ToLower()

# Build arrays of processed directory names with duplicates removed. (E.g., System32\Com\dmp and
# SysWOW64\Com\dmp can both be covered with a single entry.)
[System.Collections.ArrayList]$Wr_windir = @()
[System.Collections.ArrayList]$Wr_PF = @()

# For the Windows list, replace matching System32, SysWOW64, and Windows paths with corresponding
# AppLocker variables, then add to collection if not already present.
$Wr_raw_windir | foreach {
	$dir = $_.ToLower()
	if ($dir.StartsWith($sSystem32))     { $dir = "%SYSTEM32%\" + $dir.Substring($sSystem32.Length) }
	elseif ($dir.StartsWith($sSysWow64)) { $dir = "%SYSTEM32%\" + $dir.Substring($sSysWow64.Length) }
	elseif ($dir.StartsWith($sWindir))   { $dir = "%WINDIR%\"   + $dir.Substring($sWindir.Length)   }
    # Don't add the rule twice if it appears in both System32 and SysWOW64, since both map to %SYSTEM32%.
    if (!$Wr_windir.Contains($dir))
    {
    	$Wr_windir.Add($dir) | Out-Null
    }
}

# For the two ProgramFiles lists, replace top directory with AppLocker variable, then add to collection
# if not already present.
$Wr_raw_PF86 | foreach {
	$dir = $_.ToLower()
	if ($dir.StartsWith($sPF86))     { $dir = "%PROGRAMFILES%\" + $dir.Substring($sPF86.Length) }
	$Wr_PF.Add($dir) | Out-Null
}

$Wr_raw_PF | foreach {
	$dir = $_.ToLower()
	if ($dir.StartsWith($sPF))     { $dir = "%PROGRAMFILES%\" + $dir.Substring($sPF.Length) }
	# Possibly already added same directory from PF86; don't add again
	if (!$Wr_PF.Contains($dir))
	{
		$Wr_PF.Add($dir) | Out-Null
	}
}

####################################################################################################
# Incorporate data for EXE files to blacklist under Windir
####################################################################################################

# Incorporate the EXE blacklist into the document where the one PLACEHOLDER_WINDIR_EXEBLACKLIST
# placeholder is.
$xPlaceholder = $xDocument.SelectNodes("//PLACEHOLDER_WINDIR_EXEBLACKLIST")[0]
$xExcepts = $xPlaceholder.ParentNode

$csvExeBlacklistData = (Get-Content $ExeBlacklistData | ConvertFrom-Csv)
$csvExeBlacklistData | foreach {
    # Create a FilePublisherCondition element with the publisher attributes
    $elem = $xDocument.CreateElement("FilePublisherCondition")
    $elem.SetAttribute("PublisherName", $_.PublisherName)
    $elem.SetAttribute("ProductName", $_.ProductName)
    $elem.SetAttribute("BinaryName", $_.BinaryName)
    # Set version number range to "any"
    $elemVerRange = $xDocument.CreateElement("BinaryVersionRange")
    $elemVerRange.SetAttribute("LowSection", "*")
    $elemVerRange.SetAttribute("HighSection", "*")
    # Add the version range to the publisher condition
    $elem.AppendChild($elemVerRange) | Out-Null
    # Add the publisher condition where the placeholder is
    $xExcepts.AppendChild($elem) | Out-Null
}
# Remove the placeholder element
$xExcepts.RemoveChild($xPlaceholder) | Out-Null

Write-Host "Processing additional safe paths to whitelist..." -ForegroundColor Cyan
# Get additional whitelisted paths from the script that produces that list and incorporate them into the document
$PathsToAllow = (& $ps1_GetSafePathsToAllow)
# Add "allow" for Everyone for Exe, Dll, and Script rules
$xRuleCollections = $xDocument.SelectNodes("//RuleCollection[@Type='Exe' or @Type='Script' or @Type='Dll']")
foreach($xRuleCollection in $xRuleCollections)
{
    $PathsToAllow | foreach {
        # If path is an existing directory and doesn't have trailing "\*" appended, fix it so that it does.
        # If path is a file, don't append \*. If the path ends with \*, no need for further validation.
        # If it doesn't end with \* but Get-Item can't identify it as a file or a directory, write a warning and accept it as is.
        $pathToAllow = $_
        if (!$pathToAllow.EndsWith("\*"))
        {
            $pathItem = Get-Item $pathToAllow -Force -ErrorAction SilentlyContinue
            if ($pathItem -eq $null)
            {
                Write-Warning "Cannot verify path $pathItem; adding to rule set as is."
            }
            elseif ($pathItem -is [System.IO.DirectoryInfo])
            {
                Write-Warning "Appending `"\*`" to rule for $pathToAllow"
                $pathToAllow = [System.IO.Path]::Combine($pathToAllow, "*")
            }
        }
        $elemRule = $xDocument.CreateElement("FilePathRule")
        $elemRule.SetAttribute("Action", "Allow")
        $elemRule.SetAttribute("UserOrGroupSid", "S-1-1-0")
        $elemRule.SetAttribute("Id", [GUID]::NewGuid().Guid)
        $elemRule.SetAttribute("Name", "Additional allowed path: " + $pathToAllow)
        $elemRule.SetAttribute("Description", "Allows Everyone to execute from " + $pathToAllow)
        $elemConditions = $xDocument.CreateElement("Conditions")
        $elemCondition = $xDocument.CreateElement("FilePathCondition")
        $elemCondition.SetAttribute("Path", $pathToAllow)
        $elemConditions.AppendChild($elemCondition) | Out-Null
        $elemRule.AppendChild($elemConditions) | Out-Null
        $xRuleCollection.AppendChild($elemRule) | Out-Null
    }
}

# Incorporate path-exception rules for the user-writable directories under %windir%
# in the the EXE, DLL, and SCRIPT rules.
# Find the placeholders for Windows subdirectories, and add the path conditions there.
# Then remove the placeholders.
$xPlaceholders = $xDocument.SelectNodes("//PLACEHOLDER_WINDIR_WRITABLEDIRS")
foreach($xPlaceholder in $xPlaceholders)
{
	$xExcepts = $xPlaceholder.ParentNode
	$Wr_windir | foreach {
		$elem = $xDocument.CreateElement("FilePathCondition")
		$elem.SetAttribute("Path", $_)
		$xExcepts.AppendChild($elem) | Out-Null
	}
	$xExcepts.RemoveChild($xPlaceholder) | Out-Null
}

# Incorporate path-exception rules for the user-writable directories under %PF%
# in EXE, DLL, and SCRIPT rules.
# Find the placeholders for PF subdirectories, and add the path conditions there.
# Then remove the placeholders.
$xPlaceholders = $xDocument.SelectNodes("//PLACEHOLDER_PF_WRITABLEDIRS")
foreach($xPlaceholder in $xPlaceholders)
{
	$xExcepts = $xPlaceholder.ParentNode
	$Wr_PF | foreach {
		$elem = $xDocument.CreateElement("FilePathCondition")
		$elem.SetAttribute("Path", $_)
		$xExcepts.AppendChild($elem) | Out-Null
	}
	$xExcepts.RemoveChild($xPlaceholder) | Out-Null
}


####################################################################################################
# Begin creating dynamically-generated rule fragments. Delete old ones first.
####################################################################################################

# Delete previous set of dynamically-generated rules first
Remove-Item ([System.IO.Path]::Combine($mergeRulesDynamicDir, "*.xml"))


####################################################################################################
# Create rules for trusted publishers
####################################################################################################
Write-Host "Creating rules for trusted publishers..." -ForegroundColor Cyan

# Define an empty AppLocker policy to fill, with a blank publisher rule to use as a template.
$signerPolXml = [xml]@"
    <AppLockerPolicy Version="1">
      <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
        <FilePublisherRule Id="" Name="" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
          <Conditions>
            <FilePublisherCondition PublisherName="" ProductName="*" BinaryName="*">
              <BinaryVersionRange LowSection="*" HighSection="*" />
            </FilePublisherCondition>
          </Conditions>
        </FilePublisherRule>
      </RuleCollection>
      <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
      <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
      <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
    </AppLockerPolicy>
"@
# Get the blank publisher rule. It will be cloned to make the real publisher rules, and then this blank will be deleted.
$fprTemplate = $signerPolXml.DocumentElement.SelectNodes("//FilePublisherRule")[0]

# Run the script that produces the signer information to process. Should come in as a sequence of hashtables.
# Each hashtable must have a label, and either an exemplar or a publisher.
# fprRulesNotEmpty: Don't generate TrustedSigners.xml if it doesn't have any rules.
$fprRulesNotEmpty = $false
$signersToBuildRulesFor = (& $ps1_TrustedSigners)
$signersToBuildRulesFor | foreach {
    $label = $_.label
    if ($label -eq $null)
    {
        # Each hashtable must have a label.
        Write-Warning -Message ("Invalid syntax in $ps1_TrustedSigners. No `"label`" specified.")
    }
    else
    {
        $publisher = $product = $binaryname = ""
        $filename = ""
        $good = $false
        # Exemplar is a file signed by the publisher we want to trust. If the hashtable specifies "useProduct" = $true,
        # the AppLocker rule allows anything signed by that publisher with the same ProductName.
        if ($_.exemplar)
        {
            $filename = $_.exemplar
            $alfi = Get-AppLockerFileInformation $filename
            if ($alfi -eq $null)
            {
                Write-Warning -Message ("Cannot get AppLockerFileInformation for $filename")
            }
            elseif (!($alfi.Publisher.HasPublisherName))
            {
                Write-Warning -Message ("Cannot get publisher information for $filename")
            }
            elseif ($_.useProduct -and !($alfi.Publisher.HasProductName))
            {
                Write-Warning "Cannot get product name information for $filename"
            }
            else
            {
                # Get publisher to trust, and optionally ProductName.
                $publisher = $alfi.Publisher.PublisherName
                if ($_.useProduct)
                {
                    $product = $alfi.Publisher.ProductName
                }
                $good = $true
            }
        }
        else
        {
            # Otherwise, the hashtable must specify the exact publisher to trust (and optionally ProductName, BinaryName+collection).
            $publisher = $_.PublisherName
            $product = $_.ProductName
            $binaryName = $_.BinaryName
            $fileVersion = $_.FileVersion
            $ruleCollection = $_.RuleCollection
            if ($null -ne $publisher)
            {
                $good = $true
            }
            else
            {
                # Object isn't a hashtable, or doesn't have either exemplar or PublisherName.
                Write-Warning -Message ("Invalid syntax in $ps1_TrustedSigners")
            }
        }

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
                if ($binaryName.Length -gt 0)
                {
                    $fpr.Conditions.FilePublisherCondition.BinaryName = $binaryName
                    $fpr.Name = "$label`: Signer/product/file rule for $publisher/$product/$binaryName"
                    if ($fileVersion.Length -gt 0)
                    {
                        $fpr.Conditions.FilePublisherCondition.BinaryVersionRange.LowSection = $fileVersion
                    }
                }
            }
            if ($filename.Length -gt 0)
            {
                $fpr.Description = "Information acquired from $filename"
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
                {
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
    }
}

# Don't generate the file if it doesn't contain any rules
if ($fprRulesNotEmpty)
{
    # Delete the blank publisher rule from the rule set.
    $fprTemplate.ParentNode.RemoveChild($fprTemplate) | Out-Null

    #$signerPolXml.OuterXml | clip
    $outfile = [System.IO.Path]::Combine($mergeRulesDynamicDir, "TrustedSigners.xml")
    # Save XML as Unicode
    SaveXmlDocAsUnicode -xmlDoc $signerPolXml -xmlFilename $outfile
}

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