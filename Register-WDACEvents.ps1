function New-AppIndex {

    try {
        $MaxMSIAppIndex = Get-MAXAppIndexID -isMSIorScript -ErrorAction Stop
        $MaxPEAppIndex = Get-MAXAppIndexID -ErrorAction Stop
    } catch {
        throw $_
    }

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
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $SignerDetails,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]$AppIndex
    )

    $TempDate = Get-Date ("12/31/1610 5:00:00 PM")
    if ( (Get-Date ($SignerDetails.NotValidBefore)) -lt $TempDate -or (Get-Date ($SignerDetails.NotValidAfter)) -lt $TempDate) {
    #Microsoft arbitrarily sets some signers to be dated around the year 1600. Let's skip these
        return;
    } elseif (-not ($SignerDetails.PublisherTBSHash) -or -not ($SignerDetails.IssuerTBSHash)) {
        return;
    }

    try {
        if (-not (Find-WDACCertificate $SignerDetails.IssuerTBSHash -ErrorAction Stop)) {
            if (-not (Add-WDACCertificate -TBSHash $SignerDetails.IssuerTBSHash -CommonName $SignerDetails.IssuerName -IsLeaf $false -ErrorAction Stop)) {
                throw "Failed to add Issuer certificate."
            }
        }
        if (-not (Find-WDACCertificate $SignerDetails.PublisherTBSHash -ErrorAction Stop)) {
            if (-not (Add-WDACCertificate -TBSHash $SignerDetails.PublisherTBSHash -CommonName $SignerDetails.PublisherName -IsLeaf $true -ParentCertTBSHash $SignerDetails.IssuerTBSHash -NotValidBefore $SignerDetails.NotValidBefore -NotValidAfter $SignerDetails.NotValidAfter -ErrorAction Stop)) {
                throw "Failed to add Publisher certificate."
            }
        }
        if (-not(Add-WDACAppSigner -AppIndex $AppIndex -SignatureIndex $SignerDetails.SignatureIndex -CertificateTBSHash $SignerDetails.PublisherTBSHash -SignatureType $SignerDetails.SignatureType -PageHash $SignerDetails.PageHash -Flags $SignerDetails.Flags -PolicyBits $SignerDetails.PolicyBits -ValidatedSigningLevel $SignerDetails.ValidatedSigningLevel -VerificationError $SignerDetails.VerificationError -ErrorAction Stop)) {
        #An assumption made here is that a signer entry will not exist if the app entry didn't exist (this function is only called when the app doesn't exist in the db)
            throw "Failed to add App Signer Information."
        }
    } catch {
        throw $_
    }
}


function Register-PEEvent {
    [CmdletBinding()]
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
            
            $Var1 = (Add-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -FileName $FileName -TimeDetected $WDACEvent.TimeCreated -FirstDetectedPath $FirstDetectedPath -FirstDetectedUser $WDACEvent.User -FirstDetectedProcessID $WDACEvent.ProcessID -FirstDetectedProcessName $WDACEvent.ProcessName -SHA256AuthenticodeHash $WDACEvent.SHA256AuthenticodeHash -OriginDevice $DeviceName -EventType $WDACEvent.EventType -SigningScenario $WDACEvent.SigningScenario -OriginalFileName $WDACEvent.OriginalFileName -FileVersion $WDACEvent.FileVersion -InternalName $WDACEvent.InternalName -FileDescription $WDACEvent.FileDescription -ProductName $WDACEvent.ProductName -PackageFamilyName $WDACEvent.PackageFamilyName -UserWriteable $WDACEvent.UserWriteable -FailedWHQL $WDACEvent.FailedWHQL -BlockingPolicyID $WDACEvent.PolicyGUID -AppIndex $AppIndex -RequestedSigningLevel $WDACEvent.RequestedSigningLevel -ValidatedSigningLevel $WDACEvent.ValidatedSigningLevel -ErrorAction Stop)
            if (-not $Var1) {
                throw "Unsuccessful in adding this app to the database: $($WDACEvent.SHA256FileHash)"
            }
            foreach ($signer in $WDACEvent.SignerInfo) {
                Register-Signer -SignerDetails $signer -AppIndex $AppIndex -ErrorAction Stop
            }
        }
    } catch {
        throw $_
    }
}

function Register-MSIorScriptEvent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $WDACEvent
    )
    #TODO - Implement Function
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

    .PARAMETER WDACEvents
    Events received to pipeline input (from WDACAuditing)

    .PARAMETER NoOut
    When this is set, no output is returned.

    .INPUTS
    [PSCustomObject] Result of Get-WDACEvents

    .OUTPUTS
    Pipes out a replica of the inputs if you still need them.

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC2,PC3 -SignerInformation -CheckWhqlStatus | Register-WDACEvents -Verbose

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents -NoOut
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $WDACEvents,
        [switch]$NoOut
    )

    $MSI_OR_SCRIPT_PSOBJECT_LENGTH = 14
    
    if (-not $WDACEvents) {
        Write-Verbose "Null provided as one of the pipeline inputs to Register-WDACEvents."
        return
    }

    foreach ($WDACEvent in $WDACEvents) {
        
        if ($WDACEvent.Psobject.Properties.value.count -le ($MSI_OR_SCRIPT_PSOBJECT_LENGTH + 1)) {
        #Case 1: It is an MSI or Script

            continue; #TODO - Implement Function
            try {
                Register-MSIorScriptEvent -WDACEvent $WDACEvent -ErrorAction Stop
            } catch {
                Write-Verbose $_
            }
            
        } else {
        #Case 2: Else it is an executable, dll, driver, etc.
            try {
                Register-PEEvent -WDACEvent $WDACEvent -ErrorAction Stop
            } catch {
                Write-Verbose $_
                Write-Verbose "Failed to add this event (or its signers): $WDACEvent"
            }
        }
    }

    if (-not $NoOut) {
        return $WDACEvents
    }
}