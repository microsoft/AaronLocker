function Export-ALPolicy
{
<#
	.SYNOPSIS
		Exports AaronLocker policies to file.
	
	.DESCRIPTION
		Exports AaronLocker policies to file.
		This is NOT an export of AppLocker compatible data.
		Use this to transport an entire AaronLocker policy from one computer to another.
		It will require using Import-ALPolicyObject on the target machine to reuse it.
	
	.PARAMETER PolicyName
		Name of the AaronLocker policy to work with.
	
	.PARAMETER Policy
		The AaronLocker policy objects to export.
	
	.PARAMETER Path
		The path to export to.
		Either specify the full file path or the folder in which to place it.
		In either way, the folder must exist, if no filename was speccified it will be created based on the policy name.
	
	.EXAMPLE
		PS C:\> Export-ALPolicy
	
		Exports the current policy into the current path under its own name.
	
	.EXAMPLE
		PS C:\> Get-ALPolicy -List | Export-ALPolicy -Path C:\policies
	
		Exports all managed policies into the C:\policies folder, each under its own name.
	
	.EXAMPLE
		PS C:\> Export-ALPolicy -PolicyName 'OneDrive' -Path .\OneDrive.xml
	
		Exports the OneDrive policy to the file OneDrive.xml in the current folder.
	
	.EXAMPLE
		PS C:\> Get-ALPolicy -List | Export-ALPOlicy -Path { "C:\policies\{0} {1}.xml" -f (Get-Date -Format 'yyyy-MM-dd'), $_.Name }
	
		Exports all managed policies into the c:\policies, each timestamped and under its own name with an xml extension.
#>
	[CmdletBinding(DefaultParameterSetName = 'name')]
	Param (
		[Parameter(ParameterSetName = 'name')]
		[string]
		$PolicyName,
		
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'policy')]
		[AaronLocker.Policy[]]
		$Policy,
		
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]
		$Path = "."
	)
	
	begin
	{
		try { $PolicyName = Resolve-ALPolicy -PolicyName $PolicyName }
		catch { Write-ALError -ErrorRecord $_ -Terminate }
		
		$isFolder = $false
		if (Test-Path $resolvedPath)
		{
			$item = Get-Item -Path $resolvedPath
			if ($item.PSIsContainer) { $isFolder = $true }
		}
	}
	process
	{
		switch ($PSCmdlet.ParameterSetName)
		{
			'name'
			{
				try { $resolvedPath = Resolve-ALPath -Path $Path -Provider FileSystem -SingleItem -NewChild }
				catch { throw }
				
				if ($isFolder) { $resolvedPath = Join-Path $resolvedPath "$($PolicyName).policy.clixml" }
				Write-Verbose "Exporting policy $($PolicyName) to $($resolvedPath)"
				$script:_PolicyData[$PolicyName] | Export-Clixml -Path $resolvedPath
			}
			'policy'
			{
				# Do in process, not in begin, due to pipeline support
				try { $resolvedPath = Resolve-ALPath -Path $Path -Provider FileSystem -SingleItem -NewChild }
				catch { throw }
				
				foreach ($policyItem in $Policy)
				{
					$tempOutPath = $resolvedPath
					if ($isFolder) { $tempOutPath = Join-Path $tempOutPath "$($policyItem.Name).policy.clixml" }
					Write-Verbose "Exporting policy $($policyItem.Name) to $($tempOutPath)"
					$policyItem | Export-Clixml -Path $resolvedPath
				}
			}
		}
	}
}
