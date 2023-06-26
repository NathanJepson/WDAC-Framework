function Get-WDACEvents {
    <#
    .SYNOPSIS
    Uses WDACAuditing.psm1 module (h/t Matthew Graeber) to grab Code Integrity events from devices.
    
    .DESCRIPTION
    First this checks whether WDACAuditing module is installed on remote machine(s). If not, it is copied to the remote machine(s). (Copied to "C:\Program Files\WindowsPowerShell\Modules"). 
    Then, once the module is in place, either the Get-WDACApplockerScriptMsiEvent or Get-WDACCodeIntegrityEvent functions will be used to pull events (or both).
    You can pipe these results to Register-WDACEvents and Approve-WDACRules.
    NOTE: If you try to grab too many events at once it will take a while to get results, especially if pulled from more than one machine
    
    Author: Nathan Jepson
    License: MIT License

    .PARAMETER RemoteMachine
    The remote machine(s) to grab code integrity events from.

    .PARAMETER SkipModuleCheck
    When specified, the script will not check if WDACAuditing module is located on remote machine(s).

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
        try {
            Copy-WDACAuditing -RemoteMachine $RemoteMachine -PSModuleRoot $PSModuleRoot -ModulePath $ModulePath -ErrorAction Stop
        } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Error "PowerShell remoting is not available for those devices."
            return
        } catch {
            Write-Verbose $_
        }
    }

    Write-Verbose "Extracting events from remote machines(s)."
    $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction SilentlyContinue
    if ($sess) {
        $Events = Invoke-Command -Session $sess -ScriptBlock { 
            try {Import-Module WDACAuditing -ErrorAction Stop; Get-WDACCodeIntegrityEvent -SignerInformation -CheckWhqlStatus -MaxEvents 4 -ErrorAction Stop }
            catch {return $_}
        }
    }
    #TODO: Configure Get-WDACCodeIntegrityEvent flags and Get-WDACApplockerScriptMsiEvent flags
    #Write-Host ($Events | Format-List -Property * | Out-String)
    
    return $Events
}