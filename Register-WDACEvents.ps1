function New-AppIndex {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $MaxMSIAppIndex = Get-MAXAppIndexID -isMSIorScript -Connection $Connection -ErrorAction Stop
        $MaxPEAppIndex = Get-MAXAppIndexID -Connection $Connection -ErrorAction Stop
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
        [int]$AppIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $TempDate = Get-Date ("12/31/1610 5:00:00 PM")
    if ( (Get-Date ($SignerDetails.NotValidBefore)) -lt $TempDate -or (Get-Date ($SignerDetails.NotValidAfter)) -lt $TempDate) {
    #Microsoft arbitrarily sets some signers to be dated around the year 1600. Let's skip these
        return;
    } elseif (-not ($SignerDetails.PublisherTBSHash) -or -not ($SignerDetails.IssuerTBSHash)) {
        return;
    }

    try {
        if (-not (Find-WDACCertificate $SignerDetails.IssuerTBSHash -Connection $Connection -ErrorAction Stop)) {
            if (-not (Add-WDACCertificate -TBSHash $SignerDetails.IssuerTBSHash -CommonName $SignerDetails.IssuerName -IsLeaf $false -Connection $Connection -ErrorAction Stop)) {
                throw "Failed to add Issuer certificate."
            }
        }
        if (-not (Find-WDACCertificate $SignerDetails.PublisherTBSHash -Connection $Connection -ErrorAction Stop)) {
            if (-not (Add-WDACCertificate -TBSHash $SignerDetails.PublisherTBSHash -CommonName $SignerDetails.PublisherName -IsLeaf $true -ParentCertTBSHash $SignerDetails.IssuerTBSHash -NotValidBefore $SignerDetails.NotValidBefore -NotValidAfter $SignerDetails.NotValidAfter -Connection $Connection -ErrorAction Stop)) {
                throw "Failed to add Publisher certificate."
            }
        }
        if (-not(Add-WDACAppSigner -AppIndex $AppIndex -SignatureIndex $SignerDetails.SignatureIndex -CertificateTBSHash $SignerDetails.PublisherTBSHash -SignatureType $SignerDetails.SignatureType -PageHash $SignerDetails.PageHash -Flags $SignerDetails.Flags -PolicyBits $SignerDetails.PolicyBits -ValidatedSigningLevel $SignerDetails.ValidatedSigningLevel -VerificationError $SignerDetails.VerificationError -Connection $Connection -ErrorAction Stop)) {
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
        $WDACEvent,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
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
        $AppIndex = New-AppIndex -Connection $Connection -ErrorAction Stop

        if (-not (Find-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop)) {
            
            $Var1 = (Add-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -FileName $FileName -TimeDetected $WDACEvent.TimeCreated -FirstDetectedPath $FirstDetectedPath -FirstDetectedUser $WDACEvent.User -FirstDetectedProcessID $WDACEvent.ProcessID -FirstDetectedProcessName $WDACEvent.ProcessName -SHA256AuthenticodeHash $WDACEvent.SHA256AuthenticodeHash -OriginDevice $DeviceName -EventType $WDACEvent.EventType -SigningScenario $WDACEvent.SigningScenario -OriginalFileName $WDACEvent.OriginalFileName -FileVersion $WDACEvent.FileVersion -InternalName $WDACEvent.InternalName -FileDescription $WDACEvent.FileDescription -ProductName $WDACEvent.ProductName -PackageFamilyName $WDACEvent.PackageFamilyName -UserWriteable $WDACEvent.UserWriteable -FailedWHQL $WDACEvent.FailedWHQL -BlockingPolicyID $WDACEvent.PolicyGUID -AppIndex $AppIndex -RequestedSigningLevel $WDACEvent.RequestedSigningLevel -ValidatedSigningLevel $WDACEvent.ValidatedSigningLevel -Connection $Connection -ErrorAction Stop)
            if (-not $Var1) {
                throw "Unsuccessful in adding this app to the database: $($WDACEvent.SHA256FileHash)"
            }
            foreach ($signer in $WDACEvent.SignerInfo) {
                Register-Signer -SignerDetails $signer -AppIndex $AppIndex -Connection $Connection -ErrorAction Stop
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
        $WDACEvent,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
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

    .PARAMETER Level
    Your preferred level; when this is set, the cmdlet checks whether an apps is already trusted at the specified level, and if it is, doesn't add the code integrity event to the apps table

    .PARAMETER Fallbacks
    Backup preferred levels (see 'Level' parameter). If an app is trusted at the level of a fallback, the WDACEvent is not added to the apps table.

    .INPUTS
    [PSCustomObject] Result of Get-WDACEvents

    .OUTPUTS
    Pipes out a replica of the inputs if you still need them.

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC2,PC3 -SignerInformation -CheckWhqlStatus | Register-WDACEvents -Verbose

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents -NoOut -Level FilePublisher -Fallbacks Publisher,Hash
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $WDACEvents,
        [switch]$NoOut,
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string]$Level,
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Fallbacks
    )

    $AllLevels = $null
    if ($Level -or $Fallbacks) {
        if ($Fallbacks -and $Level) {
            $Fallbacks = $Fallbacks | Where-Object {$_ -ne $Level}
        }
        $AllLevels = @()
        if ($Level) {
            $AllLevels += $Level
        }
        if ($Fallbacks -and $Fallbacks.Count -ge 1) {
            foreach ($Fallback in $Fallbacks) {
                $AllLevels += $Fallback
            }
        }
    }

    $MSI_OR_SCRIPT_PSOBJECT_LENGTH = 14
    $Connection = New-SQLiteConnection -ErrorAction Stop
    if (-not $WDACEvents) {
        Write-Verbose "Null provided as one of the pipeline inputs to Register-WDACEvents."
        return
    }

    foreach ($WDACEvent in $WDACEvents) {
        
        $Transaction = $Connection.BeginTransaction()
   
        if ( ($Level -or $Fallbacks) -and $AllLevels.Count -ge 1) {
        #If it is already trusted at a specified level, no need to add WDACEvent to the database
            if (Get-AppTrustedNoAppEntry -WDACEvent $WDACEvent -AllPossibleLevels $AllLevels -Connection $Connection -ErrorAction Stop) {
                Write-Verbose "App $($WDACEvent.FilePath) with SHA-256 Flat Hash $($WDACEvent.SHA256FileHash) skipped registration due to meeting a higher level of trust."
                $Transaction.Rollback()
                continue;
            }
        }

        if ($WDACEvent.Psobject.Properties.value.count -le ($MSI_OR_SCRIPT_PSOBJECT_LENGTH + 1)) {
        #Case 1: It is an MSI or Script

            continue; #TODO - Implement Function
            try {
                Register-MSIorScriptEvent -WDACEvent $WDACEvent -Connection $Connection -ErrorAction Stop
                if ($AllLevels -contains "Publisher" -or $AllLevels -contains "FilePublisher") {
                    #TODO - Implement add new publishers
                }
            } catch {
                Write-Verbose $_
                $Transaction.Rollback()
                continue
            }
            
        } else {
        #Case 2: Else it is an executable, dll, driver, etc.
            try {
                Register-PEEvent -WDACEvent $WDACEvent -Connection $Connection -ErrorAction Stop
                if ($AllLevels -contains "Publisher" -or $AllLevels -contains "FilePublisher") {
                    Add-NewPublishersFromAppSigners -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop
                }
            } catch {
                Write-Verbose $_
                Write-Verbose "Failed to add this event (or its signers): $WDACEvent"
                $Transaction.Rollback()
                continue
            }
        }

        $Transaction.Commit()
    }

    $Connection.Close()
    if (-not $NoOut) {
        return $WDACEvents
    }
}