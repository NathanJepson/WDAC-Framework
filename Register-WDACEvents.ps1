function Register-Signer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $SignerDetails,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]$AppIndex,
        [switch]$MSI,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $MSI) {
        $TempDate = Get-Date ("12/31/1610 5:00:00 PM")

        if ( ((Get-Date ($SignerDetails.NotValidBefore)) -lt $TempDate) -or ((Get-Date ($SignerDetails.NotValidAfter)) -lt $TempDate)) {
            #Microsoft arbitrarily sets some signers to be dated around the year 1600. Let's skip these
            return;
        } 
    }
    
    if (-not ($SignerDetails.PublisherTBSHash)) {
        return;
    }

    try {
        if (-not (Find-WDACCertificate $SignerDetails.IssuerTBSHash -Connection $Connection -ErrorAction Stop)) {
            if (-not (Add-WDACCertificate -TBSHash $SignerDetails.IssuerTBSHash -CommonName $SignerDetails.IssuerName -Connection $Connection -ErrorAction Stop)) {
                throw "Failed to add Issuer certificate."
            }
        }
        if (-not (Find-WDACCertificate $SignerDetails.PublisherTBSHash -Connection $Connection -ErrorAction Stop)) {
            if (-not (Add-WDACCertificate -TBSHash $SignerDetails.PublisherTBSHash -CommonName $SignerDetails.PublisherName -ParentCertTBSHash $SignerDetails.IssuerTBSHash -NotValidBefore $SignerDetails.NotValidBefore -NotValidAfter $SignerDetails.NotValidAfter -Connection $Connection -ErrorAction Stop)) {
                throw "Failed to add Publisher certificate."
            }
        } else {
        #If a certificate was already in the database, but never had a parent certificate listed, or it never had NotValidBefore or NotValidAfter date.
            try {
                if (-not (Test-WDACCertificateParentCertTBSHash -TBSHash $SignerDetails.PublisherTBSHash -Connection $Connection -ErrorAction Stop)) {
                    if (-not (Set-WDACCertificateParentCertTBSHash -TBSHash $SignerDetails.PublisherTBSHash -ParentCertTBSHash $SignerDetails.IssuerTBSHash -Connection $Connection -ErrorAction Stop)) {
                        throw "Could not update parent cert."
                    }
                }
            } catch {
                Write-Verbose ($_ | Format-List -Property * | Out-String)
                Write-Warning "Could not update Parent cert for certificate with TBS hash $($SignerDetails.PublisherTBSHash)"
            }

            try {
                if (-not (Test-WDACCertificateNotValidBefore -TBSHash $SignerDetails.PublisherTBSHash -Connection $Connection -ErrorAction Stop)) {
                    if (-not (Set-WDACCertificateNotValidBefore -TBSHash $SignerDetails.PublisherTBSHash -NotValidBefore $SignerDetails.NotValidBefore -Connection $Connection -ErrorAction Stop)) {
                        throw "Could not update NotValidBefore date."
                    }
                }
            } catch {
                Write-Verbose ($_ | Format-List -Property * | Out-String)
                Write-Warning "Could not update NotValidBefore for certificate with TBS hash $($SignerDetails.PublisherTBSHash)"
            }

            try {
                if (-not (Test-WDACCertificateNotValidAfter -TBSHash $SignerDetails.PublisherTBSHash -Connection $Connection -ErrorAction Stop)) {
                    if (-not (Set-WDACCertificateNotValidAfter -TBSHash $SignerDetails.PublisherTBSHash -NotValidAfter $SignerDetails.NotValidAfter -Connection $Connection -ErrorAction Stop)) {
                        throw "Could not update NotValidAfter date."
                    }
                }
            } catch {
                Write-Verbose ($_ | Format-List -Property * | Out-String)
                Write-Warning "Could not update NotValidAfter date for certificate with TBS hash $($SignerDetails.PublisherTBSHash)"
            }
        }

        if ($MSI) {
            if (-not(Add-MsiOrScriptSigner -AppIndex $AppIndex -SignatureIndex $SignerDetails.SignatureIndex -CertificateTBSHash $SignerDetails.PublisherTBSHash -Connection $Connection -ErrorAction Stop)) {
                #An assumption made here is that a signer entry will not exist if the app entry didn't exist (this function is only called when the app doesn't exist in the db)
                throw "Failed to add msi or script signer information for app index $AppIndex"
            }
        } else {
            if (-not(Add-WDACAppSigner -AppIndex $AppIndex -SignatureIndex $SignerDetails.SignatureIndex -CertificateTBSHash $SignerDetails.PublisherTBSHash -SignatureType $SignerDetails.SignatureType -PageHash $SignerDetails.PageHash -Flags $SignerDetails.Flags -PolicyBits $SignerDetails.PolicyBits -ValidatedSigningLevel $SignerDetails.ValidatedSigningLevel -VerificationError $SignerDetails.VerificationError -Connection $Connection -ErrorAction Stop)) {
                #An assumption made here is that a signer entry will not exist if the app entry didn't exist (this function is only called when the app doesn't exist in the db)
                throw "Failed to add App signer information for app index $AppIndex"
            }
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

    try {
        if (-not (Find-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop)) {
            
            $Var1 = (Add-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -FileName $FileName -TimeDetected $WDACEvent.TimeCreated -FirstDetectedPath $FirstDetectedPath -FirstDetectedUser $WDACEvent.User -FirstDetectedProcessID $WDACEvent.ProcessID -FirstDetectedProcessName $WDACEvent.ProcessName -SHA256AuthenticodeHash $WDACEvent.SHA256AuthenticodeHash -SHA256SipHash $WDACEvent.SIPHash256 -OriginDevice $DeviceName -EventType $WDACEvent.EventType -SigningScenario $WDACEvent.SigningScenario -OriginalFileName $WDACEvent.OriginalFileName -FileVersion $WDACEvent.FileVersion -InternalName $WDACEvent.InternalName -FileDescription $WDACEvent.FileDescription -ProductName $WDACEvent.ProductName -PackageFamilyName $WDACEvent.PackageFamilyName -UserWriteable $WDACEvent.UserWriteable -FailedWHQL $WDACEvent.FailedWHQL -BlockingPolicyID $WDACEvent.PolicyGUID -RequestedSigningLevel $WDACEvent.RequestedSigningLevel -ValidatedSigningLevel $WDACEvent.ValidatedSigningLevel -Connection $Connection -ErrorAction Stop)
            if (-not $Var1) {
                throw "Unsuccessful in adding this app to the database: $($WDACEvent.SHA256FileHash)"
            }
            foreach ($signer in $WDACEvent.SignerInfo) {
                Register-Signer -SignerDetails $signer -AppIndex ((Get-WDACApp -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop).AppIndex) -Connection $Connection -ErrorAction Stop
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

    if ($WDACEvent.PSComputerName) {
        $DeviceName = $WDACEvent.PSComputerName
    } else {
    #Assume that the events were pulled from this local device if no PSComputerName attribute is present
        $DeviceName = hostname
    }

    try {
        if (-not (Find-MSIorScript -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop)) {
            
            $Var1 = (Add-MSIorScript -SHA256FlatHash $WDACEvent.SHA256FileHash -TimeDetected $WDACEvent.TimeCreated -FirstDetectedPath $WDACEvent.FilePath -FirstDetectedUser $WDACEvent.User -FirstDetectedProcessID $WDACEvent.ProcessID -SHA256AuthenticodeHash $WDACEvent.SHA256AuthenticodeHash -SHA256SipHash $WDACEvent.SIPHash256 -UserWriteable $WDACEvent.UserWriteable -Signed $WDACEvent.Signed -OriginDevice $DeviceName -EventType $WDACEvent.EventType -Connection $Connection -ErrorAction Stop)
            if (-not $Var1) {
                throw "Unsuccessful in adding this app to the database: $($WDACEvent.SHA256FileHash)"
            }
            foreach ($signer in $WDACEvent.SignerInfo) {
                Register-Signer -SignerDetails $signer -AppIndex ((Get-MsiorScript -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop).AppIndex) -MSI -Connection $Connection -ErrorAction Stop
            }
        }
    } catch {
        throw $_
    }
}


filter Register-WDACEvents {

    <#
    .SYNOPSIS
    Adds events retrieved from Get-WDACEvent to the trust database.

    .DESCRIPTION
    Add individual apps, signers, certificates, and MSIs or scripts to the trust database based on the schema of events returned from WDACAuditing. 
    You can also pipe-in results from the Get-WDACFiles cmdlet (which is the same format as events from WDACAuditing.)
    You will need to pipe the results of Get-WDACEvents or Get-WDACFiles to this function.

    Author: Nathan Jepson
    License: MIT License

    .INPUTS
    [PSCustomObject] Result of Get-WDACEvents or Get-WDACFiles

    .OUTPUTS
    Pipes out a replica of the inputs if you still need them.

    .PARAMETER WDACEvent
    Events as PSCustomObjects piped from Get-WDACEvents or Get-WDACFiles

    .PARAMETER NoOut
    When this is set, no output is returned.

    .PARAMETER Level
    Your preferred level; when this is set, the cmdlet checks whether an apps is already trusted at the specified level, and if it is, doesn't add the code integrity event to the apps table

    .PARAMETER Fallbacks
    Backup preferred levels (see 'Level' parameter). If an app is trusted at the level of a fallback, the WDACEvent is not added to the apps table.

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents

    .EXAMPLE
    Get-WDACFiles -RemoteMachine PC1 -NoShadowCopy -ScanPath "C:\Program Files (x86)\" -UserPEs -NoScript -Verbose | Register-WDACEvents -Level Publisher -Fallbacks Hash -Verbose

    .EXAMPLE
    Get-WDACEvents -RemoteMachine PC2,PC3 -SignerInformation -CheckWhqlStatus | Register-WDACEvents -Verbose

    .EXAMPLE
    Get-WDACEvents | Register-WDACEvents -NoOut -Level FilePublisher -Fallbacks Publisher,Hash
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        $WDACEvent,
        [Parameter(ValueFromPipeline = $false)]
        [switch]$NoOut,
        [Parameter(ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string]$Level,
        [Parameter(ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Fallbacks
    )

    $AllLevels = $null
    $SkipRegister = $false
    $MSI_OR_SCRIPT_PSOBJECT_LENGTH = 14

    if ($Level -or $Fallbacks) {
        if ($Fallbacks -and $Level) {
            $Fallbacks = $Fallbacks | Where-Object {$_ -ne $Level}
        }
        $AllLevels = @()
        if ($Level) {
            $AllLevels += $Level
        }
        if (($Fallbacks) -and ($Fallbacks.Count -ge 1)) {
            foreach ($Fallback in $Fallbacks) {
                $AllLevels += $Fallback
            }
        }
    }

    $Connection = New-SQLiteConnection -ErrorAction Stop
    if (-not $WDACEvent) {
        $Connection.Close()
        Write-Verbose "Null provided as one of the pipeline inputs to Register-WDACEvents."
        return
    }

    $Transaction = $Connection.BeginTransaction()

    if ( ($Level -or $Fallbacks) -and $AllLevels.Count -ge 1) {
    #If it is already trusted at a specified level, no need to add WDACEvent to the database
        if (Get-AppTrustedNoAppEntry -WDACEvent $WDACEvent -AllPossibleLevels $AllLevels -Connection $Connection -ErrorAction Stop) {
            Write-Verbose "App $($WDACEvent.FilePath) with SHA-256 Flat Hash $($WDACEvent.SHA256FileHash) skipped registration due to meeting a higher level of trust."
            $Transaction.Rollback()
            $SkipRegister = $true
        }
    }

    if (-not $SkipRegister) {
        if ($WDACEvent.Psobject.Properties.value.count -le ($MSI_OR_SCRIPT_PSOBJECT_LENGTH + 1)) {
            #Case 1: It is an MSI or Script
            try {
                Register-MSIorScriptEvent -WDACEvent $WDACEvent -Connection $Connection -ErrorAction Stop
                if (($AllLevels -contains "Publisher") -or ($AllLevels -contains "FilePublisher")) {
                    Add-NewPublishersFromAppSigners -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop
                }
            } catch {
                Write-Verbose ($_ | Format-List -Property * | Out-String)
                Write-Verbose "Failed to add this event (or its signers): $WDACEvent"
                $Transaction.Rollback()
            }
        } else {
        #Case 2: Else it is an executable, dll, driver, etc.
            try {
                Register-PEEvent -WDACEvent $WDACEvent -Connection $Connection -ErrorAction Stop
                if (($AllLevels -contains "Publisher") -or ($AllLevels -contains "FilePublisher")) {
                    Add-NewPublishersFromAppSigners -SHA256FlatHash $WDACEvent.SHA256FileHash -Connection $Connection -ErrorAction Stop
                }
            } catch {
                Write-Verbose ($_ | Format-List -Property * | Out-String)
                Write-Verbose "Failed to add this event (or its signers): $WDACEvent"
                $Transaction.Rollback()
                
            }
        }

        if ($Connection.AutoCommit -eq $false) {
            $Transaction.Commit()
        }        
    }

    $Connection.Close()
    
    if (-not ($SkipRegister -or $NoOut)) {
        $WDACEvent
    }
}