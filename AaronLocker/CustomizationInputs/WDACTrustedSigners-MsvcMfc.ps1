<#
.SYNOPSIS
Script designed to be dot-sourced into TrustedSigners.ps1 that supports the creation of publisher rules for observed MSVC*.DLL and MFC*.DLL files.

.DESCRIPTION
There are already MSVC* and MFC* DLLs in Windows - this script also allows redistributable DLLs that often ship with other products and are installed into user-writable directories.
This output allows any version of signed MSVC* or MFC* DLLs that shipped with a known version of Visual Studio.
This is not the same as allowing anything signed by Microsoft or is part of Visual Studio - just the runtime library support DLLs.

This file can be updated as additional MSVC* and MFC* DLLs appear in event logs when observed executing from user-writable directories.
Add more files as they are identified.

See TrustedSigners.ps1 for details about how this input is used.

#>

###########################################################################
# Visual Studio 2008
###########################################################################

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "7251ADC0F732CF409EE462E335BB99544F2DD40F";
PublisherName = "Microsoft Corporation";
ProductName = "Microsoft® Visual Studio® 2008";
FileName = "MFC90U.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName = "Microsoft® Visual Studio® 2008";
FileName = "MSVCP90.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName = "Microsoft® Visual Studio® 2008";
FileName = "MSVCR90.DLL";
}

###########################################################################
# Visual Studio 2010
###########################################################################

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "7251ADC0F732CF409EE462E335BB99544F2DD40F";
PublisherName = "Microsoft Corporation";
ProductName = "Microsoft® Visual Studio® 2010";
FileName = "msvcp100.dll";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® .NET Framework";
FileName = "MSVCR100_CLR0400.DLL";
}

###########################################################################
# Visual Studio 2012
###########################################################################

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio® 2012";
FileName = "MFC110.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio® 2012";
FileName = "MFC110.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio® 2012";
FileName = "MSVCP110.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio® 2012";
FileName = "MSVCP110.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio® 2012";
FileName = "MSVCR110.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio® 2012";
FileName = "MSVCR110.DLL";
}

###########################################################################
# Visual Studio 2013
###########################################################################

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MFC120.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MFC120.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MFC120U.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MFC120U.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MSVCP120.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MSVCP120.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA";
IssuerTBSHash = "27543A3F7612DE2261C7228321722402F63A07DE";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MSVCR120.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
FileName = "MSVCR120.DLL";
}

###########################################################################
# Visual Studio 2015
###########################################################################

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2015";
FileName = "MSVCP140.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2015";
FileName = "VCRUNTIME140.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2015";
FileName = "MFC140U.DLL";
}

###########################################################################
# Visual Studio 2017
###########################################################################

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2017";
FileName = "MSVCP140.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2017";
FileName = "VCRUNTIME140.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName = "MICROSOFT® VISUAL STUDIO® 2017";
FileName = "MFC140.DLL";
}

###########################################################################
# Visual Studio 10
###########################################################################

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "MICROSOFT® VISUAL STUDIO® 10";
FileName = "MFC100U.DLL";
}

###########################################################################
# Visual Studio 2015, 2017, 2019
###########################################################################

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio®";
FileName = "MSVCP140.DLL";
}

@{
label = "MSVC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio®";
FileName = "VCRUNTIME140.DLL";
}

@{
label = "MFC runtime DLL";
IssuerName = "Microsoft Code Signing PCA 2011";
IssuerTBSHash = "F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E";
PublisherName = "Microsoft Corporation";
ProductName   = "Microsoft® Visual Studio®";
FileName = "MFC140U.DLL";
}

