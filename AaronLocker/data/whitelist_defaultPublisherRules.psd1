@{
	Common = @(
		@{
			# Allow Microsoft-signed OneDrive EXE and DLL files with the OneDrive product name; 
			# This rule doesn't cover all of OneDrive's files because they include files from other products (Visual Studio, QT5, etc.)
			label		  = "Microsoft OneDrive (partial)"
			PublisherName = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName   = "MICROSOFT ONEDRIVE"
		}
		
		@{
			label		   = "Microsoft-signed MSI files"
			RuleCollection = "Msi"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
		}
		
		@{
			# Windows' built-in troubleshooting often involves running Microsoft-signed scripts in the user's profile
			label		   = "Microsoft-signed script files"
			RuleCollection = "Script"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
		}
	)
	MSFC_MVC = @(
		###########################################################################
		# Visual Studio 2005
		###########################################################################
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2005"
			BinaryName	   = "MSVCP80.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2005"
			BinaryName	   = "MSVCR80.DLL"
		}
		
		###########################################################################
		# Visual Studio 2008
		###########################################################################
		
		@{
			label		   = "MFC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2008"
			BinaryName	   = "MFC90U.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2008"
			BinaryName	   = "MSVCP90.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2008"
			BinaryName	   = "MSVCR90.DLL"
		}
		
		###########################################################################
		# Visual Studio 2010
		###########################################################################
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2010"
			BinaryName	   = "MSVCP100.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2010"
			BinaryName	   = "MSVCR100_CLR0400.DLL"
		}
		
		###########################################################################
		# Visual Studio 2012
		###########################################################################
		
		@{
			label		   = "MFC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2012"
			BinaryName	   = "MFC110.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2012"
			BinaryName	   = "MSVCP110.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2012"
			BinaryName	   = "MSVCR110.DLL"
		}
		
		###########################################################################
		# Visual Studio 2013
		###########################################################################
		
		@{
			label		   = "MFC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2013"
			BinaryName	   = "MFC120.DLL"
		}
		
		@{
			label		   = "MFC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2013"
			BinaryName	   = "MFC120U.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2013"
			BinaryName	   = "MSVCP120.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2013"
			BinaryName	   = "MSVCR120.DLL"
		}
		
		###########################################################################
		# Visual Studio 2015
		###########################################################################
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2015"
			BinaryName	   = "MSVCP140.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2015"
			BinaryName	   = "VCRUNTIME140.DLL"
		}
		
		###########################################################################
		# Visual Studio 2017
		###########################################################################
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2017"
			BinaryName	   = "MSVCP140.DLL"
		}
		
		@{
			label		   = "MSVC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 2017"
			BinaryName	   = "VCRUNTIME140.DLL"
		}
		
		###########################################################################
		# Visual Studio 10
		###########################################################################
		
		@{
			label		   = "MFC runtime DLL"
			RuleCollection = "Dll"
			PublisherName  = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
			ProductName    = "MICROSOFT® VISUAL STUDIO® 10"
			BinaryName	   = "MFC100U.DLL"
		}
	)
}