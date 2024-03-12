if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    Write-Verbose "The current file is in the SignedModules folder."
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WDACFileScanner.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WDACFileScanner.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\WDACFileScanner.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Copy-WDACFileScanner.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Copy-WDACFileScanner.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\Copy-WDACFileScanner.psm1")
}

function Get-WDACFiles {
    <#
    .SYNOPSIS
    Scan files to extract WDAC info and format it the same way as Matthew Graber's WDACAuditing module

    .DESCRIPTION
    This module checks for the presence of the WDACFileScanner.psm1 module (located in the resources folder of WDAC-Framework), and if it is 
    not present, it will copy it to the PS modules folder on the remote machine. 

    On the remote machine, the Get-SystemDriver command is used to grab information from files (and they don't actually have to be driver files, they 
    can be UserMode binaries as well -- just provide the UserPEs flag).
    The information is formatted just like the result of Get-WDACEvents. 

    If the -NoScript flag is provided, no file scanning for scripts or MSI files is performed

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER Audit
    "Indicates that this cmdlet searches the Code Integrity Audit log for drivers. It does not perform a full system scan."
    Source: https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver

    .PARAMETER NoScript
    When specified, this cmdlet doesn't return MSIs or Scripts.

    .PARAMETER NoShadowCopy
    "Indicates that the Volume Snapshot Service (VSS) does not make a shadow copy of the disk while the scan runs. This parameter could cause an incomplete scan for a system that is running.
    If a scan fails due to VSS errors caused by low disk space on the target drive, this cmdlet prompts you to specify this parameter."
    Source: https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver

    .PARAMETER OmitPaths
    "Specifies an array of paths that this cmdlet omits from the scan. We recommend that you omit C:\Windows.old."
    Source: https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver

    .PARAMETER PathToCatroot
    "Specifies the path of the CatRoot folder. Specify this parameter to scan a remote or mounted drive."
    Source: https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver

    .PARAMETER ScanPath
    The directory you are scanning.

    .PARAMETER ScriptFileNames
    Not specified on MS documentation.

    .PARAMETER UserPEs
    Allow for the cmdlet to scan UserMode files (highly recommended in many scenarios)

    .PARAMETER RemoteMachine
    The remote machines you would like to scan the designated ScanPath on

    .PARAMETER SkipModuleCheck
    Skip the check for whether the WDACFileScanner.psm1 module is on the remote machine (faster)
    #>

    [CmdletBinding()]
    param (
        [switch]$Audit,
        [switch]$NoScript,
        [switch]$NoShadowCopy,
        [string[]]$OmitPaths,
        [string]$PathToCatroot,
        [string]$ScanPath,
        [switch]$ScriptFileNames,
        [switch]$UserPEs,
        [string[]]$RemoteMachine,
        [switch]$SkipModuleCheck
    )

    begin {
        if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
            $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
            Write-Verbose "The current file is in the SignedModules folder."
        } else {
            $PSModuleRoot = $PSScriptRoot
        }
    
        $Signed = $false
        if (Test-Path (Join-Path $PSModuleRoot -ChildPath ".\SignedModules\Resources\WDACFileScanner.psm1")) {
            $Signed = $true
        }
    
        if ($Signed) {
            $ModulePath = ".\SignedModules\Resources\WDACFileScanner.psm1"
        } else {
            $ModulePath = ".\Resources\WDACFileScanner.psm1"
        }

        $ImportModule = $false
        if ($RemoteMachine) {
            $ImportModule = $true
        }

        $PEFilesResults = @()
        $MSIorScriptFilesResults = @()

        $GetWDACFilesScriptBlock = {
        Param(
            $Audit,
            $NoScript,
            $NoShadowCopy,
            $OmitPaths,
            $PathToCatroot,
            $ScanPath,
            $ScriptFileNames,
            $UserPEs,
            $IsVerbose
        )

            try {
                Import-Module -Name "WDACFileScanner"
                
                Get-SystemDriversModified -Audit:$Audit -NoScript:$NoScript -NoShadowCopy:$NoShadowCopy -OmitPaths $OmitPaths -PathToCatroot $PathToCatroot -ScanPath $ScanPath -ScriptFileNames:$ScriptFileNames -UserPEs:$UserPEs -ErrorAction Stop
            } catch {
                if ($IsVerbose) {
                    Write-Warning ($_ | Format-List -Property * | Out-String)
                }
                return $null
            }
        }
    }

    process {

        try {
        #This clears all the "Skipped" properties on apps and msi_or_script so they are all 0 when Approve-WDACRules cmdlet is used
            Clear-AllWDACSkipped -ErrorAction Stop
        } catch {
            Write-Verbose $_
            Write-Warning "Could not clear all the `"Skipped`" properties on apps and scripts. Clear attribute manually before running Approve-WDACRules."
        }
        

        if ((-not $SkipModuleCheck) -and $RemoteMachine) {
            try {
                Copy-WDACFileScanner -RemoteMachine $RemoteMachine -PSModuleRoot $PSModuleRoot -ModulePath $ModulePath -ErrorAction Stop
            } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                Write-Error "PowerShell remoting is not available for those devices."
                return
            } catch {
                Write-Verbose $_
            }
        }

        if (-not $RemoteMachine) {
            Write-Verbose "Extracting file information for WDAC from local machine."

            $PEFilesResults,$MSIorScriptFilesResults = PowerShell {
                Param(
                    $Audit,
                    $NoScript,
                    $NoShadowCopy,
                    $OmitPaths,
                    $PathToCatroot,
                    $ScanPath,
                    $ScriptFileNames,
                    $UserPEs,
                    $ModulePath,
                    $PSModuleRoot
                )

                try {
                    Import-Module (Join-Path $PSModuleRoot -ChildPath $ModulePath)
                    
                    Get-SystemDriversModified -Audit:$Audit -NoScript:$NoScript -NoShadowCopy:$NoShadowCopy -OmitPaths $OmitPaths -PathToCatroot $PathToCatroot -ScanPath $ScanPath -ScriptFileNames:$ScriptFileNames -UserPEs:$UserPEs -ErrorAction Stop
                } catch {
                    Write-Error ($_ | Format-List -Property * | Out-String)
                    return $null
                }
            } -args $Audit.ToBool(),$NoScript.ToBool(),$NoShadowCopy.ToBool(),$OmitPaths,$PathToCatroot,$ScanPath,$ScriptFileNames.ToBool(),$UserPEs.ToBool(),$ModulePath,$PSModuleRoot

        } else {
            Write-Verbose "Extracting file information for WDAC from remote machines(s)."
            $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction SilentlyContinue

            $PEFilesResults,$MSIorScriptFilesResults = Invoke-Command -Session $sess -ScriptBlock $GetWDACFilesScriptBlock -ArgumentList $Audit,$NoScript,$NoShadowCopy,$OmitPaths,$PathToCatroot,$ScanPath,$ScriptFileNames,$UserPEs,$VerbosePreference
        }
    }

    end {
        if ($sess) {
            $sess | Remove-PSSession
        }

        if ($NoScript) {
            return $PEFilesResults
        } else {
            return $PEFilesResults,$MSIorScriptFilesResults
        }
    }
}

Export-ModuleMember -Function Get-WDACFiles