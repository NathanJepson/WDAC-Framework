$ThisIsASignedModule = $false
if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Copy-WDACAuditing.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Copy-WDACAuditing.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\Copy-WDACAuditing.psm1")
}

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
    The remote machine(s) to grab code integrity events from. Omit this parameter to grab events from just the local machine.

    .PARAMETER SkipModuleCheck
    When specified, the script will not check if WDACAuditing module is located on remote machine(s).

    .PARAMETER MaxEvents
    Specifies the maximum number of events that Get-WDACCodeIntegrityEvent and Get-WDACApplockerScriptMsiEvent return. The default is to return all the events.

    .PARAMETER PEEvents
    Get non-MSI and non-Script-Based WDAC events (i.e., uses Get-WDACCodeIntegrityEvent). By default this is already enabled.

    .PARAMETER MSIorScripts
    Get MSI or Script-based events (i.e., uses Get-WDACApplockerScriptMsiEvent). By default this is already enabled.

    .PARAMETER ShowAllowedEvents
    Parameter for Get-WDACApplockerScriptMsiEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER SignerInformation
    Parameter for both Get-WDACApplockerScriptMsiEvent and Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER SinceLastPolicyRefresh
    Parameter for both Get-WDACApplockerScriptMsiEvent and Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER User
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER Kernel
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER Audit
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER Enforce
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER CheckWhqlStatus
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER IgnoreNativeImagesDLLs
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER IgnoreDenyEvents
    Parameter for Get-WDACCodeIntegrityEvent. See WDACAuditing.psm1 for usage.

    .PARAMETER PolicyGUID
    Specify that you only want events associated with a specific WDAC Policy (by GUID)

    .PARAMETER PolicyName
    Specify that you only want events associated with a specific WDAC Policy (by name)

    .EXAMPLE
    Get-WDACEvents -MaxEvents 4 -SignerInformation -Verbose

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC1,PC2 -SkipModuleCheck

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC1 -PEEvents -MaxEvents 2 -SinceLastPolicyRefresh -CheckWhqlStatus

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC1,PC2 -MSIorScripts -ShowAllowedEvents -SinceLastPolicyRefresh

    #>

    [CmdletBinding(DefaultParameterSetName = 'Both')]
    param(
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [ValidateNotNullOrEmpty()]
        [string[]]$RemoteMachine,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$SkipModuleCheck,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [Int64]$MaxEvents,
        [Parameter(ParameterSetName = 'PEEvents')]
        [switch]$PEEvents,
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$MSIorScripts,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$ShowAllowedEvents,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$SignerInformation,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$SinceLastPolicyRefresh,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [switch]$User,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [switch]$Kernel,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$Audit,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [Parameter(ParameterSetName = 'MSIorScripts')]
        [switch]$Enforce,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [switch]$CheckWhqlStatus,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [switch]$IgnoreNativeImagesDLLs,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [switch]$IgnoreDenyEvents,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [string]$PolicyGUID,
        [Parameter(ParameterSetName = 'Both')]
        [Parameter(ParameterSetName = 'PEEvents')]
        [string]$PolicyName
    )

    begin {
        if ($ThisIsASignedModule) {
            Write-Verbose "The current file is in the SignedModules folder."
        }

        if ($PolicyGUID -and $PolicyName) {
            throw "Cannot provide both a policy GUID and a policy name."
        }

        if ($PolicyName) {
            if (-not (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop)) {
                throw "There are no policies by this policy name: $PolicyName in the database."
            }
            $PolicyGUID = (Get-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop).PolicyGUID
        }
        if ($PolicyGUID) {
            if (-not (Find-WDACPolicy -PolicyGUID $PolicyGUID -ErrorAction Stop)) {
                throw "There are no policies in the database with this GUID: $PolicyGUID"
            }
        }

        if (($PolicyGUID -or $PolicyName) -and (($MSIorScripts) -or ((-not $MSIorScripts) -and (-not $PEEvents)))) {
            Write-Warning "Filtering by policy is not available for MSI or Script events, this parameter has been ignored for these types of event logs."
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

        $PE_And_MSI = $false
        if ( ($PEEvents -and $MSIorScripts) -or ( (-not $PEEvents) -and (-not $MSIorScripts))) {
            $PE_And_MSI = $true
        }

        $PEScriptBlock = {
        Param(
            $MaxEvents,
            $User,
            $Kernel,
            $Audit,
            $Enforce,
            $SinceLastPolicyRefresh,
            $SignerInformation,
            $CheckWhqlStatus,
            $IgnoreNativeImagesDLLs,
            $IgnoreDenyEvents,
            $ImportModule,
            $PolicyGUID
        )
            try {
                if ($ImportModule) {
                    Import-Module -Name "WDACAuditing"
                }
                Get-WDACCodeIntegrityEvent -MaxEvents $MaxEvents -PolicyGUID $PolicyGUID -User:$User -Kernel:$Kernel -Audit:$Audit -Enforce:$Enforce -SinceLastPolicyRefresh:$SinceLastPolicyRefresh -SignerInformation:$SignerInformation -CheckWhqlStatus:$CheckWhqlStatus -IgnoreNativeImagesDLLs:$IgnoreNativeImagesDLLs -IgnoreDenyEvents:$IgnoreDenyEvents -ErrorAction Stop 
            } catch {
                Write-Verbose $_
                return $null
            }
        }

        $MSIorScript_ScriptBlock = {
        Param(
            $MaxEvents,
            $SignerInformation,
            $ShowAllowedEvents,
            $SinceLastPolicyRefresh,
            $ImportModule,
            $Audit,
            $Enforce
        )
            try {
                if ($ImportModule) {
                    Import-Module -Name "WDACAuditing"
                } 
                Get-WDACApplockerScriptMsiEvent -MaxEvents $MaxEvents -SignerInformation:$SignerInformation -ShowAllowedEvents:$ShowAllowedEvents -SinceLastPolicyRefresh:$SinceLastPolicyRefresh -Audit:$Audit -Enforce:$Enforce -ErrorAction Stop 
            } catch {
                Write-Verbose $_
                return $null
            }
        }

        $PEEventResults = @()
        $MSIorScriptEventResults = @()

        $ImportModule = $false
        if ($RemoteMachine) {
            $ImportModule = $true
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

        #Check whether WDACAuditing should be copied if SkipModuleCheck is not set and we are running on remote machines
        if (-not $SkipModuleCheck -and $RemoteMachine) {
            try {
                Copy-WDACAuditing -RemoteMachine $RemoteMachine -PSModuleRoot $PSModuleRoot -ModulePath $ModulePath -ErrorAction Stop
            } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                Write-Error "PowerShell remoting is not available for those devices."
                return
            } catch {
                Write-Verbose $_
            }
        }

        if (-not $RemoteMachine) {
            Write-Verbose "Extracting events from local machine."
            if ($PE_And_MSI -or $PEEvents) {
                $PEEventResults = Invoke-Command -ScriptBlock $PEScriptBlock -ArgumentList $MaxEvents,$User,$Kernel,$Audit,$Enforce,$SinceLastPolicyRefresh,$SignerInformation,$CheckWhqlStatus,$IgnoreNativeImagesDLLs,$IgnoreDenyEvents,$ImportModule,$PolicyGUID
            }
            if ($PE_And_MSI -or $MSIorScripts) {
                $MSIorScriptEventResults = Invoke-Command -ScriptBlock $MSIorScript_ScriptBlock -ArgumentList $MaxEvents,$SignerInformation,$ShowAllowedEvents,$SinceLastPolicyRefresh,$ImportModule,$Audit,$Enforce
            }
        } else {
            Write-Verbose "Extracting events from remote machines(s)."
            $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction SilentlyContinue
            if ($sess) {
                if ($PE_And_MSI -or $PEEvents) {
                    $PEEventResults = Invoke-Command -Session $sess -ScriptBlock $PEScriptBlock -ArgumentList $MaxEvents,$User,$Kernel,$Audit,$Enforce,$SinceLastPolicyRefresh,$SignerInformation,$CheckWhqlStatus,$IgnoreNativeImagesDLLs,$IgnoreDenyEvents,$ImportModule,$PolicyGUID
                }
                if ($PE_And_MSI -or $MSIorScripts) {
                    $MSIorScriptEventResults = Invoke-Command -Session $sess -ScriptBlock $MSIorScript_ScriptBlock -ArgumentList $MaxEvents,$SignerInformation,$ShowAllowedEvents,$SinceLastPolicyRefresh,$ImportModule,$Audit,$Enforce
                }
            }
        }
    }

    end {
        if ($sess) {
            $sess | Remove-PSSession
        }

        if ($PE_And_MSI) {
            $result = @()
            foreach ($WDACFileInfo in $PEEventResults) {
                $result += $WDACFileInfo
            }
            foreach ($WDACFileInfo in $MSIorScriptEventResults) {
                $result += $WDACFileInfo
            }
            return $result
        } elseif ($PEEvents) {
            return $PEEventResults
        } elseif ($MSIorScripts) {
            return $MSIorScriptEventResults
        }
    }
}

Export-ModuleMember -Function Get-WDACEvents