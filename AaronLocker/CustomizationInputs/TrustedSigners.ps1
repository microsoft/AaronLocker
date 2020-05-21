<#
.SYNOPSIS
Customizable script used by Create-Policies.ps1 that identifies publishers or publisher+product/file combinations to trust.

.DESCRIPTION
TrustedSigners.ps1 outputs a sequence of hashtables that specify a label, and either a literal publisher name, or a path to a signed file to use as an example.

Each hashtable has a "label" property that is incorporated into the rule name and description.

Each hashtable also has either a "PublisherName" or an "exemplar" property:
* "PublisherName" is a literal canonical name identifying a publisher to trust.
  When using PublisherName, you can also add optional properties:
  * "ProductName", to restrict trust just to that product by that publisher; with "ProductName" you can also add "BinaryName" to restrict to a specific internal file name,
    and optionally then "FileVersion" as well to specify a minimum allowed file version.
    When using BinaryName, you should also specify an explicit RuleCollection, to reduce the number of rules. (E.g., no sense in having a Script rule allowing "MSVCP80.DLL".)
  * "RuleCollection", to apply the trust only within a single RuleCollection. RuleCollection must be one of "Exe", "Dll", "Script", or "Msi", and it is CASE-SENSITIVE.
* "exemplar" is the path to a signed file; the publisher to trust is extracted from that signature. When using exemplar, you can also add an optional "useProduct" boolean value indicating whether to restrict publisher trust only to that file's product name. If "useProduct" is not specified, all files signed by the publisher are trusted.

Examples showing possible combinations:

    # Trust everything by a specific publisher
    @{
    label = "Trust all Contoso";
    PublisherName = "O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US";
    }

    # Trust all DLLs by a specific publisher
    @{
    label = "Trust all Contoso DLLs";
    PublisherName = "O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US";
    RuleCollection = "Dll";
    }

    # Trust a specific product published by a specific publisher
    @{
    label = "Trust all CUSTOMAPP files published by Contoso";
    PublisherName = "O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US";
    ProductName = "CUSTOMAPP";
    }
    
    # Trust any version of a specific signed file by a specific publisher/product
    # RuleCollection must be one of Exe, Dll, Script, or Msi, and is CASE-SENSITIVE
    @{
    label = "Trust Contoso's SAMPLE.DLL in CUSTOMAPP";
    PublisherName = "O=CONTOSO, L=SEATTLE, S=WASHINGTON, C=US";
    ProductName = "CUSTOMAPP";
    BinaryName = "SAMPLE.DLL";
    FileVersion = "10.0.15063.0";
    RuleCollection = "Dll"; 
    }

    # Trust everything signed by the same publisher as the exemplar file (Autoruns.exe)
    @{
    label = "Trust the publisher of Autoruns.exe";
    exemplar = "C:\Program Files\Sysinternals\Autoruns.exe";
    }

    # Trust everything with the same publisher and product as the exemplar file (LuaBuglight.exe)
    @{
    label = "Trust everything with the same publisher and product as LuaBuglight.exe";
    exemplar = "C:\Program Files\Utils\LuaBuglight.exe";
    useProduct = $true
    }
#>


@{
# Allow Microsoft-signed files with the Microsoft Teams product name.
label = "Microsoft Teams";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "MICROSOFT TEAMS";
}

@{
label = "Microsoft-signed MSI files";
RuleCollection = "Msi";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
}

@{
# Windows' built-in troubleshooting often involves running Microsoft-signed scripts in the user's profile
label = "Microsoft-signed script files";
RuleCollection = "Script";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
}

# During Windows upgrade, setup loads %OSDRIVE%\$WINDOWS.~BT\SOURCES\GENERALTEL.DLL, which loads two other DLLs in the same directory
@{
label = "Allow selected files from %OSDRIVE%\$WINDOWS.~BT\SOURCES during Windows upgrade";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "MICROSOFT® WINDOWS® OPERATING SYSTEM";
BinaryName = "GENERALTEL.DLL";
}
@{
label = "Allow selected files from %OSDRIVE%\$WINDOWS.~BT\SOURCES during Windows upgrade";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "MICROSOFT® WINDOWS® OPERATING SYSTEM";
BinaryName = "WDSCORE.DLL";
}
@{
label = "Allow selected files from %OSDRIVE%\$WINDOWS.~BT\SOURCES during Windows upgrade";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "MICROSOFT® WINDOWS® OPERATING SYSTEM";
BinaryName = "AEINV.DLL";
}

# Allow protected content run in MS Edge
@{
label = "MS Edge content protection";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "WIDEVINE CONTENT DECRYPTION MODULE";
RuleCollection = "Dll";
}

# Uncomment this block if Google Chrome is installed to ProgramFiles.
# Google Chrome runs some code in the user profile even when Chrome is installed to Program Files.
# This creates publisher rules that allow those components to run.
# Note that PublisherName used to be "O=GOOGLE INC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US"
<#
    @{
    label = "Google Chrome SWReporter tool";
    RuleCollection = "Exe";
    PublisherName = "O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CA, C=US";
    ProductName = "SOFTWARE REPORTER TOOL";
    BinaryName = "SOFTWARE_REPORTER_TOOL.EXE";
    }
    @{
    label = "Google Chrome Cleanup";
    RuleCollection = "Dll";
    PublisherName = "O=ESET, SPOL. S R.O., L=BRATISLAVA, C=SK";
    ProductName = "CHROME CLEANUP";
    }
    @{
    label = "Google Chrome Cleanup";
    RuleCollection = "Dll";
    PublisherName = "O=ESET, SPOL. S R.O., L=BRATISLAVA, S=SLOVAKIA, C=SK";
    ProductName = "CHROME CLEANUP";
    }
    @{
    label = "Google Chrome Protector";
    RuleCollection = "Dll";
    PublisherName = "O=ESET, SPOL. S R.O., L=BRATISLAVA, S=SLOVAKIA, C=SK";
    ProductName = "CHROME PROTECTOR";
    }
#>

# Uncomment this block to allow popular non-Microsoft remote meeting products
<#
    @{
    label = "WebEx";
    PublisherName = "O=CISCO WEBEX LLC, L=SAN JOSE, S=CALIFORNIA, C=US";
    }

    @{
    label = "Zoom";
    PublisherName = "O=ZOOM VIDEO COMMUNICATIONS, INC., L=SAN JOSE, S=CALIFORNIA, C=US";
    }
#>

# Allow MSVC/MFC redistributable DLLs. Dot-source the MSVC/MFC DLL include file in this directory
. ([System.IO.Path]::Combine( [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path), "TrustedSigners-MsvcMfc.ps1"))

