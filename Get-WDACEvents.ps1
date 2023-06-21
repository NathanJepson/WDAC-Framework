function Get-WDACEvents {
    <#
    .SYNOPSIS
    Uses WDACAuditing.psm1 module (h/t Matthew Graeber) to grab Code Integrity events from devices.
    
    .DESCRIPTION
    First this checks whether WDACAuditing module is installed on local machine. If not, it is copied to the remote machine. (Copied to "C:\Program Files\WindowsPowerShell\Modules"). 
    Then, once the module is in place, either the Get-WDACApplockerScriptMsiEvent or Get-WDACCodeIntegrityEvent functions will be used to pull events (or both).
    You can pipe these results to Register-WDACEvents and Approve-WDACRules.
    NOTE: If you try to grab too many events at once it will take a while to get results, especially if pulled from more than one machine
    
    Author: Nathan Jepson
    License: MIT License

    .PARAMETER RemoteMachine
    The remote machine to grab code integrity events from, or a list of machines

    .PARAMETER SkipModuleCheck
    When specified, the script will not check if WDACAuditing module is located on remote machine.

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC1 -SkipModuleCheck

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC1,PC2
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RemoteMachine,
        [switch]$SkipModuleCheck
    )

    if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
        Write-Verbose "The current file is in the SignedModules folder."
    } else {
        $PSModuleRoot = $PSScriptRoot
    }

    $Signed = $false
    if (Test-Path (Join-Path $PSModuleRoot -ChildPath ".\SignedModules\WDACAuditing\WDACAuditing.psm1")) {
        $Signed = $true
    }

    if ($Signed) {
        $ModulePath = ".\SignedModules\WDACAuditing\WDACAuditing.psm1"
    } else {
        $ModulePath = ".\WDACAuditing\WDACAuditing.psm1"
    }

    if (-not $SkipModuleCheck) {

        $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction SilentlyContinue

        $Result = Invoke-Command -Session $sess -ScriptBlock {
            $IsModulePresent = Test-Path "$($Env:Programfiles)\WindowsPowerShell\Modules\WDACAuditing\WDACAuditing.psm1"
            if (-not ($IsModulePresent)) {
                New-Item -ItemType Directory -Name "WDACAuditing" -Path "$($Env:Programfiles)\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue
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
            $Result += @{IsModulePresent = $IsModulePresent; SysDrive = $SysDrive}
            return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
        }

        #I believe you have to remove the session here otherwise you can't make individual connections to the machines that you need to copy files to (if you aren't using SMB)
        $sess | Remove-PSSession

        $iterator = 0; #Used to denote when a notice of file copying should be written.
        $jobs = @()
        $Result | ForEach-Object {
            if (-not $_.IsModulePresent) {
            #Case: Module WDACAuditing.psm1 is not yet installed on the remote machine
                if ($iterator -eq 0) {
                    Write-Host "Copying module WDACAuditing to machines which don't have it...."
                }

                $TempDrive = ( ($_.SysDrive -split '\:')[0])
                
                $ScriptBlock = {
                    
                    Param(
                        $PSComputerName,
                        $TempDrive,
                        $PSModuleRoot,
                        $ModulePath
                    )

                #This script block uses SMB as the first try and PowerShell remoting (WinRM) as the second try
                #Note: PowerShell remoting will fail if a non-audit WDAC policy is on the remote machine (due to Constrained Language Mode)
                    try {
                        Copy-Item -Path (Join-Path $PSModuleRoot -ChildPath $ModulePath) -Destination "\\$PSComputerName\$TempDrive`$\Program Files\WindowsPowerShell\Modules\WDACAuditing\"
                    } catch {
                        try {
                            $sess = New-PSSession -ComputerName $PSComputerName; 
                            Copy-Item -ToSession $sess -Path (Join-Path $PSModuleRoot -ChildPath $ModulePath) -Destination "$TempDrive`:\Program Files\WindowsPowerShell\Modules\WDACAuditing\"
                            $sess | Remove-PSSession
                        } catch {
                            #FIXME / TODO
                            ##TODO: UseConstrainedLanguageMode workaround 
                            #In other words: Provide an alternate method to copy files to remote when SMB isn't available and Constrained Language is enabled on remote.
                        }
                    }
                }
                
                $jobs += (Start-Job -Name ("CopyWDACAuditing_" + $_.PSComputerName) -ScriptBlock $ScriptBlock -ArgumentList $_.PSComputerName,$TempDrive,$PSModuleRoot,$ModulePath)
                $iterator += 1;
            }
        }

        foreach ($job in $jobs) {
            $job | Wait-Job | Format-List -Property *
        }
    }
    
    $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction SilentlyContinue
    $Events = Invoke-Command -Session $sess -ScriptBlock { 
        try {Import-Module WDACAuditing -ErrorAction Stop; Get-WDACCodeIntegrityEvent -SignerInformation -CheckWhqlStatus -MaxEvents 4 -ErrorAction Stop }
        catch {Write-Verbose $_; return $null}
    }
    #TODO: Configure Get-WDACCodeIntegrityEvent flags and Get-WDACApplockerScriptMsiEvent flags

    Write-Host ($Events | Format-List -Property * | Out-String)

    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        $MoreThanOne = $false
        for ($i = 0; $i -lt $Error.Count; $i++) {
            
            if ($Error[$i].CategoryInfo.Reason -eq "PSRemotingTransportException") {
                if (-not $MoreThanOne) {
                    Write-Host 'PowerShell Remoting (WinRM) failed on these devices:'
                    $MoreThanOne = $true
                }
                $ErrorDevice = $Error[$i].ErrorDetails.Message.Split("]")[0]
                $ErrorDevice = $ErrorDevice.Substring(1)
                Write-Host $ErrorDevice
            }
        }
    }

}