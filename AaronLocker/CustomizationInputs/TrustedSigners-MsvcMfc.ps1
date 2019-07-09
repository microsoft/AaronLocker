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
# Visual Studio 2005
###########################################################################

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2005";
BinaryName = "MSVCP80.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2005";
BinaryName = "MSVCR80.DLL";
}

###########################################################################
# Visual Studio 2008
###########################################################################

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2008";
BinaryName = "MFC90U.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2008";
BinaryName = "MSVCP90.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2008";
BinaryName = "MSVCR90.DLL";
}

###########################################################################
# Visual Studio 2010
###########################################################################

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2010";
BinaryName = "MSVCP100.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2010";
BinaryName = "MSVCR100_CLR0400.DLL";
}

###########################################################################
# Visual Studio 2012
###########################################################################

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2012";
BinaryName = "MFC110.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2012";
BinaryName = "MSVCP110.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2012";
BinaryName = "MSVCR110.DLL";
}

###########################################################################
# Visual Studio 2013
###########################################################################

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
BinaryName = "MFC120.DLL";
}

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
BinaryName = "MFC120U.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
BinaryName = "MSVCP120.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2013";
BinaryName = "MSVCR120.DLL";
}

###########################################################################
# Visual Studio 2015
###########################################################################

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2015";
BinaryName = "MSVCP140.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2015";
BinaryName = "VCRUNTIME140.DLL";
}

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "MICROSOFT® VISUAL STUDIO® 2015";
BinaryName = "MFC140U.DLL";
}

###########################################################################
# Visual Studio 2017
###########################################################################

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2017";
BinaryName = "MSVCP140.DLL";
}

@{
label = "MSVC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 2017";
BinaryName = "VCRUNTIME140.DLL";
}

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName = "MICROSOFT® VISUAL STUDIO® 2017";
BinaryName = "MFC140.DLL";
}

###########################################################################
# Visual Studio 10
###########################################################################

@{
label = "MFC runtime DLL";
RuleCollection = "Dll";
PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
ProductName   = "MICROSOFT® VISUAL STUDIO® 10";
BinaryName = "MFC100U.DLL";
}

