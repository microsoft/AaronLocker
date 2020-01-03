<#
.SYNOPSIS
Customizable script used by Create-Policies-WDAC.ps1 that identifies publishers or publisher+product/file combinations to trust.

.DESCRIPTION
WDACTrustedSigners.ps1 outputs a sequence of hashtables that specify a label, and either a signer or file rule.

Each hashtable has a "label" property that is incorporated into the rule name and description, where appropriate.

Each hashtable also has either information to formulate a signer rule for WDAC or an "exemplar" property:
All information needed to formulate a signer rule can be found on WDAC block signature correlation events (EventID 3089) or by querying the certificate directly.
* "IssuerName" is the common name (CN) of the intermediate cert in the cert chain and is found as the Issuer on a leaf certificate.
* "IssuerTBSHash" is the TBS hash value of the intermediate cert in the cert chain.
* "PublisherName" is the CN of the leaf certificate
  When using PublisherName, you can also add optional properties:
  * "ProductName", to restrict trust just to that product by that publisher (e.g. "Microsoft Teams")
  * "FileName" is the original filename property of the signed file and can be used to authorize only specific binaries signed by the Publisher.
  * "FileVersion" is the minimum allowed file version for the named binary or all binaries from the specified Publisher.
* "exemplar" is the path to a signed file; all information to construct the rule is extracted from that file's signature and signed attributes.
    When using exemplar, you can also add optional properties:
  * "level" is the WDAC rule level used with New-CIPolicyRule and defaults to Publisher
  * "useProduct" boolean value indicating whether to restrict publisher trust only to that file's product name. 

Examples showing possible combinations:

    # Trust everything by a specific publisher
    @{
    label = "Trust all Contoso";
    IssuerName = "Symantec Class 3 SHA256 Code Signing CA - G2";
    IssuerTBSHash = "7F25CBD37DCDC0E0D93E0D477C4BC0C54231379E6CAF1023841E1F0D96467A6C";
    PublisherName = "Contoso Software";
    }

    # Trust any version of a specific signed file by a specific publisher 
    @{
    label = "Trust Contoso's SAMPLE.DLL";
    IssuerName = "Symantec Class 3 SHA256 Code Signing CA - G2";
    IssuerTBSHash = "7F25CBD37DCDC0E0D93E0D477C4BC0C54231379E6CAF1023841E1F0D96467A6C";
    PublisherName = "Contoso Software";
    FileName = "SAMPLE.DLL";
    }

    # Trust a specific product published by a specific publisher
    @{
    label = "Trust all CUSTOMAPP files published by Contoso";
    IssuerName = "Symantec Class 3 SHA256 Code Signing CA - G2";
    IssuerTBSHash = "7F25CBD37DCDC0E0D93E0D477C4BC0C54231379E6CAF1023841E1F0D96467A6C";
    PublisherName = "Contoso Software";
    ProductName = "CUSTOMAPP";
    }
    
    # Trust only files with version greater or equal to 10.0.0.0 published by a specific publisher
    @{
    label = "Trust all files with version 10.0.0.0 or greater published by Contoso";
    IssuerName = "Symantec Class 3 SHA256 Code Signing CA - G2";
    IssuerTBSHash = "7F25CBD37DCDC0E0D93E0D477C4BC0C54231379E6CAF1023841E1F0D96467A6C";
    PublisherName = "Contoso Software";
    FileVersion = "10.0.0.0";
    }
    
    # Trust only versions of a specific signed file greater or equal to 10.0.0.0 by a specific publisher 
    @{
    label = "Trust Contoso's SAMPLE.DLL version 10.0.0.0 or greater";
    IssuerName = "Symantec Class 3 SHA256 Code Signing CA - G2";
    IssuerTBSHash = "7F25CBD37DCDC0E0D93E0D477C4BC0C54231379E6CAF1023841E1F0D96467A6C";
    PublisherName = "Contoso Software";
    FileName = "SAMPLE.DLL";
    FileVersion = "10.0.0.0";
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


<#
@{
# Allow Microsoft-signed files with the Microsoft Teams product name.
label = "Microsoft Teams";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName = "MICROSOFT TEAMS";
}
#>

@{
# Trust everything signed with the GitHub Desktop publisher
label = "Trust the publisher of GitHub Desktop";
exemplar = $env:USERPROFILE+"\AppData\Local\GitHubDesktop\GitHubDesktop.exe";
}


@{
# Trust Update.exe signed by the publisher of Microsoft Teams.
label = "Trust Update.exe signed by the publisher of Microsoft Teams";
exemplar = $env:USERPROFILE+"\AppData\Local\Microsoft\Teams\Update.exe";
level = "Publisher";
useProduct = $true;
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

# Allow MSVC/MFC redistributable DLLs. Dot-source the MSVC/MFC DLL include file in this directory
# . ([System.IO.Path]::Combine( [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path), "TrustedSigners-MsvcMfc.ps1"))

