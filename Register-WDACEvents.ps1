function New-AppIndex {

    $MaxMSIAppIndex = Get-MAXAppIndexID -isMSIorScript
    $MaxPEAppIndex = Get-MAXAppIndexID

    if (-not $MaxMSIAppIndex -and -not $MaxPEAppIndex ) {
        return 1;
    }

    if (-not $MaxMSIAppIndex -and $MaxPEAppIndex) {
        return ($MaxPEAppIndex + 1)
    } elseif ($MaxMSIAppIndex -and -not $MaxPEAppIndex) {
        return ($MaxMSIAppIndex + 1)
    }

    if ($MaxMSIAppIndex -gt $MaxPEAppIndex) {
        return ($MaxMSIAppIndex + 1)
    } else {
        return ($MaxPEAppIndex + 1)
    }
}

function Register-Signer {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $SignerDetails
    )
}

function Register-PEEvent {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $WDACEvent
    )

    $FileName = Split-Path $WDACEvent.FilePath -Leaf
    $FirstDetectedPath = Split-Path $WDACEvent.FilePath

    if ($WDACEvent.PSComputerName) {
        $DeviceName = $WDACEvent.PSComputerName
    } else {
    #Assume that the events were pulled from this local device if no PSComputerName attribute is present
        $DeviceName = hostname
    }

    $AppIndex = $null

    try {
        $AppIndex = New-AppIndex -ErrorAction Stop

        if (-not (Find-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -ErrorAction Stop)) {
            
            $Var1 = (Add-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -FileName $FileName -TimeDetected $WDACEvent.TimeCreated -FirstDetectedPath $FirstDetectedPath -FirstDetectedUser $WDACEvent.User -FirstDetectedProcessID $WDACEvent.ProcessID -FirstDetectedProcessName $WDACEvent.ProcessName -SHA256AuthenticodeHash $WDACEvent.SHA256AuthenticodeHash -OriginDevice $DeviceName -EventType $WDACEvent.EventType -SigningScenario $WDACEvent.SigningScenario -OriginalFileName $WDACEvent.OriginalFileName -FileVersion $WDACEvent.FileVersion -InternalName $WDACEvent.InternalName -FileDescription $WDACEvent.FileDescription -ProductName $WDACEvent.ProductName -PackageFamilyName $WDACEvent.PackageFamilyName -UserWriteable $WDACEvent.UserWriteable -FailedWHQL $WDACEvent.FailedWHQL -BlockingPolicyID $WDACEvent.PolicyGUID -AppIndex $AppIndex -ErrorAction Stop)
            if (-not $Var1) {
                throw "Unsuccessful in adding this app: $($WDACEvent.SHA256FileHash)"
            }
            foreach ($signer in $WDACEvent.SignerInfo) {
                #TODO
            }
        }
    } catch {
        throw $_
    }
}

function Register-MSIorScriptEvent {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $WDACEvent
    )
}


filter Register-WDACEvents {

    <#
    .SYNOPSIS
    Adds events retrieved from Get-WDACEvent to the trust database.

    .DESCRIPTION
    Add individual apps, signers, certificates, and MSIs or scripts to the trust database based on the schema of events returned from WDACAuditing. 
    You will need to pipe the results of Get-WDACEvents to this function.

    Author: Nathan Jepson
    License: MIT License

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC2,PC3 -SignerInformation -CheckWhqlStatus | Register-WDACEvents -Verbose

    .INPUTS
    [PSCustomObject] Result of Get-WDACEvents

    .OUTPUTS
    Pipes out a replica of the inputs if you still need them.
    #>

    $MSI_OR_SCRIPT_PSOBJECT_LENGTH = 14
    
    if (-not $_) {
        Write-Verbose "Null provided as one of the pipeline inputs to Register-WDACEvents."
        return
    } else {
        Write-Verbose "But we're going to execute this script anyway."
    }

    foreach ($WDACEvent in $_) {
        
        if ($WDACEvent.Psobject.Properties.value.count -le ($MSI_OR_SCRIPT_PSOBJECT_LENGTH + 1)) {
        #Case 1: It is an MSI or Script

            continue; #FIXME
            try {
                Register-MSIorScriptEvent -WDACEvent $WDACEvent -ErrorAction Stop
            } catch {
                Write-Verbose $_
            }
            
        } else {
        #Case 2: Else it is an executable, dll, driver, etc.
            try {
                
                Register-PEEvent -WDACEvent $WDACEvent -ErrorAction Stop #FIXME
            } catch {
                Write-Verbose $_
                Write-Verbose "Failed event: $WDACEvent"
            }
        }
    }

    return $_
}