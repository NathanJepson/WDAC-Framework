$ThisIsASignedModule = $false
if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

function Update-RemoteModules {

    <#
    .SYNOPSIS
    This function updates WDACAuditing.psm1 and WDACFileScanner.psm1 on remote devices

    .DESCRIPTION
    This module copies WDACFileScanner.psm1 and/or WDACAuditing.psm1 to remote devices in the $($Env:Programfiles)\WindowsPowerShell\Modules\
    directory. If there are versions of the file present in the "SignedModules" directory, those files are copied instead.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER WDACAuditing
    Use this switch if you want to explicitly state that you want to copy WDACAuditing 
    (and then don't use the WDACFileScanner switch if you ONLY want to copy this module)

    .PARAMETER WDACFileScanner
    Use this switch if you want to explicitly state that you want to copy WDACFileScanner 
    (and then don't use the WDACAuditing switch if you ONLY want to copy this module)

    .PARAMETER RemoteMachines
    What devices you want to update the modules for
    #>

    [CmdletBinding()]
    Param (
        [Alias("Audititng")]
        [switch]$WDACAuditing,
        [Alias("FileScanner")]
        [switch]$WDACFileScanner,
        [Alias("Computer","Computers","PC","PCs","Device","Devices")]
        [string[]]$RemoteMachines
    )

    if ($ThisIsASignedModule) {
        Write-Verbose "The current file is in the SignedModules folder."
    }

    try {

        if ($WDACAuditing -or (-not ($WDACAuditing -or $WDACFileScanner))) {
            if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\WDACAuditing\WDACAuditing.psm1")) {
                $ModulePath = (Join-Path $PSModuleRoot -ChildPath "SignedModules\WDACAuditing\WDACAuditing.psm1")
                Write-Verbose "WDAC Auditing module is signed."
            } else {
                $ModulePath = Join-Path $PSModuleRoot -ChildPath "WDACAuditing\WDACAuditing.psm1"
            }
            
            $sess = New-PSSession $RemoteMachines -ErrorAction SilentlyContinue

            if (-not $sess) {
                throw New-Object System.Management.Automation.Remoting.PSRemotingTransportException
            }

            $Result = Invoke-Command -ErrorAction SilentlyContinue -Session $sess -ScriptBlock {
                $IsModulePresent = Test-Path "$($Env:Programfiles)\WindowsPowerShell\Modules\WDACAuditing"
                if (-not ($IsModulePresent)) {
                    New-Item -ItemType Directory -Name "WDACAuditing" -Path "$($Env:Programfiles)\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue | Out-Null
                }
                $SysDrive = $null
                if ($PSVersionTable.PSEdition -eq "Core") {
                    $SysDrive =  (Get-CimInstance -Class Win32_OperatingSystem -ComputerName localhost -Property SystemDrive | Select-Object -ExpandProperty SystemDrive)
                } elseif ($PSVersionTable.PSEdition -eq "Desktop") {
                    $SysDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
                } else {
                #Otherwise, attempt to probe C:\ as the primary Windows drive in the rest of the script (failing if needed)
                    $SysDrive = "C:"
                }
        
                $Result = @()
                $Result += @{SysDrive = $SysDrive}
                return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
            }
            $sess | Remove-PSSession

            $iterator = 0; #Used to denote when a notice of file copying should be written.
            $jobs = @()
            $Result | ForEach-Object {
                if ($_.SysDrive) {
                #Case: Module WDACAuditing.psm1 is not yet installed on the remote machine
                    if ($iterator -eq 0) {
                        Write-Host "Copying WDAC auditing module to remote machines..."
                    }
        
                    $TempDrive = ( ($_.SysDrive -split '\:')[0])
                    
                    $ScriptBlock = {
                    #This script block uses SMB as the first try and PowerShell remoting (WinRM) as the second try
                    #Note: PowerShell remoting will fail if a non-audit WDAC policy is on the remote machine (due to Constrained Language Mode)
                        Param(
                            $PSComputerName,
                            $TempDrive,
                            $ModulePath
                        )
        
                        try {
                            Copy-Item -Path $ModulePath -Destination "\\$PSComputerName\$TempDrive`$\Program Files\WindowsPowerShell\Modules\WDACAuditing\" -ErrorAction Stop
                        } catch {
                            try {
                                $sess = New-PSSession -ComputerName $PSComputerName -ErrorAction Stop; 
                                Copy-Item -ToSession $sess -Path $ModulePath -Destination "$TempDrive`:\Program Files\WindowsPowerShell\Modules\WDACAuditing\" -ErrorAction Stop
                                $sess | Remove-PSSession
                            } catch {
                                #FIXME / TODO
                                ##TODO: UseConstrainedLanguageMode workaround 
                                #In other words: Provide an alternate method to copy files to remote when SMB isn't available and Constrained Language is enabled on remote.
                            }
                        }
                    }
                    
                    $jobs += (Start-Job -Name ("CopyWDACAuditing_" + $_.PSComputerName) -ScriptBlock $ScriptBlock -ArgumentList $_.PSComputerName,$TempDrive,$ModulePath)
                    $iterator += 1;
                }
            }
        
            Write-Verbose ("Copy job count: " + $jobs.Count)
        
            foreach ($job in $jobs) {
                $job | Wait-Job | Out-Null
            }
        }

        if ($WDACFileScanner -or (-not ($WDACAuditing -or $WDACFileScanner))) {
            

            if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WDACFileScanner.psm1")) {
                $ModulePath = (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WDACFileScanner.psm1")
                Write-Verbose "The File Scanner module is signed."
            } else {
                $ModulePath = Join-Path $PSModuleRoot -ChildPath "Resources\WDACFileScanner.psm1"
            }
            
            $sess = New-PSSession $RemoteMachines -ErrorAction SilentlyContinue

            if (-not $sess) {
                throw New-Object System.Management.Automation.Remoting.PSRemotingTransportException
            }

            $Result = Invoke-Command -ErrorAction SilentlyContinue -Session $sess -ScriptBlock {
                $IsModulePresent = Test-Path "$($Env:Programfiles)\WindowsPowerShell\Modules\WDACFileScanner"
                if (-not ($IsModulePresent)) {
                    New-Item -ItemType Directory -Name "WDACFileScanner" -Path "$($Env:Programfiles)\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue | Out-Null
                }
                $SysDrive = $null
                if ($PSVersionTable.PSEdition -eq "Core") {
                    $SysDrive =  (Get-CimInstance -Class Win32_OperatingSystem -ComputerName localhost -Property SystemDrive | Select-Object -ExpandProperty SystemDrive)
                } elseif ($PSVersionTable.PSEdition -eq "Desktop") {
                    $SysDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
                } else {
                #Otherwise, attempt to probe C:\ as the primary Windows drive in the rest of the script (failing if needed)
                    $SysDrive = "C:"
                }
        
                $Result = @()
                $Result += @{SysDrive = $SysDrive}
                return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
            }
            $sess | Remove-PSSession

            $iterator = 0; #Used to denote when a notice of file copying should be written.
            $jobs = @()
            $Result | ForEach-Object {
                if ($_.SysDrive) {
                #Case: Module WDACAuditing.psm1 is not yet installed on the remote machine
                    if ($iterator -eq 0) {
                        Write-Host "Copying WDAC file scanner module to remote machines..."
                    }
        
                    $TempDrive = ( ($_.SysDrive -split '\:')[0])
                    
                    $ScriptBlock = {
                    #This script block uses SMB as the first try and PowerShell remoting (WinRM) as the second try
                    #Note: PowerShell remoting will fail if a non-audit WDAC policy is on the remote machine (due to Constrained Language Mode)
                        Param(
                            $PSComputerName,
                            $TempDrive,
                            $ModulePath
                        )
        
                        try {
                            Copy-Item -Path $ModulePath -Destination "\\$PSComputerName\$TempDrive`$\Program Files\WindowsPowerShell\Modules\WDACFileScanner\" -ErrorAction Stop
                        } catch {
                            try {
                                $sess = New-PSSession -ComputerName $PSComputerName -ErrorAction Stop; 
                                Copy-Item -ToSession $sess -Path $ModulePath -Destination "$TempDrive`:\Program Files\WindowsPowerShell\Modules\WDACFileScanner\" -ErrorAction Stop
                                $sess | Remove-PSSession
                            } catch {
                                #FIXME / TODO
                                ##TODO: UseConstrainedLanguageMode workaround 
                                #In other words: Provide an alternate method to copy files to remote when SMB isn't available and Constrained Language is enabled on remote.
                            }
                        }
                    }
                    
                    $jobs += (Start-Job -Name ("CopyWDACFileScanner_" + $_.PSComputerName) -ScriptBlock $ScriptBlock -ArgumentList $_.PSComputerName,$TempDrive,$ModulePath)
                    $iterator += 1;
                }
            }
        
            Write-Verbose ("Copy job count: " + $jobs.Count)
        
            foreach ($job in $jobs) {
                $job | Wait-Job | Out-Null
            }
        }

    } catch {
        throw ($_ | Format-List -Property * | Out-String)
    }
}

Export-ModuleMember -Function Update-RemoteModules