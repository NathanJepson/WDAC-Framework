$AppsToSkip = @{}
$AppsToBlock = @{}
$AppsToPurge = @{}
$AppComments = @{}
$SpecificFileNameLevels = @{}

function Test-ValidVersionNumber {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$VersionNumber
    )

    return ($VersionNumber -match "^(0|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))(0|(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))){3}$")
}

function Get-YesOrNoPrompt {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt
    )

    Write-Host ($Prompt + " (Y/N): ") -NoNewline
    while ($true) {
        $InputString = Read-Host
        if ($InputString.ToLower() -eq "y") {
            return $true
        } elseif ($InputString.ToLower() -eq "n") {
            return $false
        } else {
            Write-Host "Not a valid option. Please supply y or n."
        }
    }
}

function Get-LevelPrompt {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Levels
    )

    if (-not $Levels) {
        $Levels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    }

    Write-Host ($Prompt + ": (" + ($Levels -join ",") + ")")
    while ($true) {
        $InputString = Read-Host -Prompt "Option Selection"
        if (-not ($Levels -contains $InputString)) {
            Write-Host ("Not a valid option. Please supply one of these options: (" + ($Levels -join ",") + ")")
        } else {
            return $InputString
        }
    }
}

function Get-SpecificFileNameLevelPrompt {
    [CmdletBinding()]
    Param (
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        [string[]]$Levels
    )

    if (-not $Levels) {
        $Levels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")
    }

    Write-Host ("Select a SpecificFileNameLevel: (" + ($Levels -Join ",") + ")")
    $SpecificFileNameLevel = Read-Host -Prompt "Option Selection"
    while (-not ($Levels -contains $SpecificFileNameLevel)) {
        $SpecificFileNameLevel = Read-Host -Prompt "Not a valid selection. Please select one of these options: ($(($Levels -Join ",")))"
    }

    return $SpecificFileNameLevel
}

function Get-WDACConferredTrust {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $AppInfo,
        $CertInfoAndMisc,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $AppTrustLevels,
        $SpecificFileNameLevelList
    )

    $Options = "([Y] (Yes); [N] (NO); [S] (SKIP); [B] (BLOCK); [/ or COMM] (Add a comment about the app); [A or E] (Expand / View App Info); [C] (Expand / View Certificate + Publisher Info); [T] (View Trust for this App for Respective Rule Levels); [V] (Change Specific FileName Level))"
    $TrustedLevels = ($AppTrustLevels.PSObject.Properties | Where-Object {$_.Value -eq $true} | Select-Object Name).Name

    if ($TrustedLevels) {
        Write-Warning "App is already trusted at a separate rule level."
    }

    Write-Host ($Prompt + ": " + $Options)
    while ($true) {
        $InputString = Read-Host -Prompt "Option Selection"
        if ($InputString.ToLower() -eq "y") {
            return $true
        } elseif ($InputString.ToLower() -eq "n") {
            if ($TrustedLevels) {
                Write-Host "Cannot untrust an app which is already trusted at a separate rule level." -BackgroundColor Red
                Write-Host ("Options: " + $Options)
                continue
            }
            return $false
        } elseif ($InputString.ToLower() -eq "s") {
            $AppsToSkip.Add($AppInfo.SHA256FlatHash,$true)
            return $false
        } elseif ($InputString.ToLower() -eq "e" -or $InputString.ToLower() -eq "a") {
            $AppInfo | Out-Host
            Write-Host ("Options: " + $Options)
        }
        elseif ($InputString.ToLower() -eq "c") {
            if ($CertInfoAndMisc) {
                foreach ($Signer in $CertInfoAndMisc) {
                    $Signer | Select-Object SignatureIndex, SignerInfo, LeafCert, PcaCertificate | Format-List -Property * | Out-Host
                }
            } else {
                Write-Host "No associated certificate information."
            }
            
            Write-Host ("Options: " + $Options)
        }
        elseif ($InputString.ToLower() -eq "t") {
            $AppTrustLevels | Out-Host
            Write-Host ("Options: " + $Options)
        } elseif ($InputString.ToLower() -eq "b") {
            $AppsToBlock.Add($AppInfo.SHA256FlatHash,$true)
            return $false
        } elseif ($InputString -eq "/" -or $InputString.ToLower() -eq "comm") {
            if ($AppComments[$AppInfo.SHA256FlatHash]) {
                if (-not (Get-YesOrNoPrompt -Prompt "There is already a comment for this app. Overwrite previous comment?")) {
                    continue
                }
                $TempComment = Read-Host -Prompt "Overwrite previous comment"
                $AppComments[$AppInfo.SHA256FlatHash] = $TempComment
                continue
            }
            $TempComment = Read-Host -Prompt "Enter your comment about this app"
            $AppComments.Add($AppInfo.SHA256FlatHash,$TempComment)
        } elseif ($InputString.ToLower() -eq "v") {
            if ($SpecificFileNameLevelList.Count -le 0 -or (-not $SpecificFileNameLevelList)) {
                Write-Host "Unable to change SpecificFileNameLevel, as these properties of the app entry are not set: `"OriginalFileName`",`"InternalName`",`"FileDescription`",`"ProductName`",`"PackageFamilyName`""
                continue
            }
            $SpecificFileNameLevel = Get-SpecificFileNameLevelPrompt -Levels $SpecificFileNameLevelList
            $SpecificFileNameLevels.Add($AppInfo.SHA256FlatHash,$SpecificFileNameLevel)
            Write-Host ($Prompt + ": " + $Options)
        }
        else {
            Write-Host ("Not a valid option. Select one of these options: " + $Options)
        }
    }
}

function Get-RuleToSignerMapping {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Signers,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt
    )

    $Options = "[A] (ALL of them); "

    foreach ($Signer in $Signers) {
        $Options += "[$($Signer.SignatureIndex)] (Signature Index $($Signer.SignatureIndex)); "
    }

    foreach ($Signer in $Signers) {
        $Signer | Select-Object SignatureIndex, SignerInfo, LeafCert, PcaCertificate | Format-List -Property * | Out-Host
    }

    Write-Host ( $Prompt + ": " + $Options )
    while ($true) {
        $InputString = Read-Host -Prompt "Option Selection"
        if ($InputString.ToLower() -eq "a") {
            return "a"
        } else {
            $NotFound = $true
            foreach ($Signer in $Signers) {
                if ($Signer.SignatureIndex -eq $InputString) {
                    $NotFound = $false
                }
            }
            if ($NotFound) {
                Write-Host ("Not a valid option. Select one of these options: " + $Options)
                continue
            } else {
                return $InputString
            }
        }
    }
}

function Write-WDACConferredTrust {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrimaryKeyPart1,
        [string]$PrimaryKeyPart2,
        [switch]$Untrusted,
        [switch]$TrustedDriver,
        [switch]$TrustedUserMode,
        [switch]$Block,
        [string]$Comment,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [string]$PolicyID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Level,
        $VersioningType,
        [switch]$ApplyVersioningToEntirePolicy,
        $CurrentVersionNum,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if ($Untrusted -and ($Level -eq "Hash")) {
            #This will only write to the apps table (assumed that only a hash entry has 'untrusted' written to it)
                
            if (-not (Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -Level "Hash" -Untrusted $Untrusted.ToBool() -Connection $Connection -ErrorAction Stop)) {
                throw "Unable to set `"Untrusted`" status for app with hash $PrimaryKeyPart1 ."
            }
            return
        }

        switch ($Level) {
            "Hash" {
                foreach ($Result in ((Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -Level "Hash" -UserMode $TrustedUserMode.ToBool() -Driver $TrustedDriver.ToBool() -Block $Block.ToBool() -Connection $Connection -ErrorAction Stop))) {
                    if (-not $Result) {
                        throw "Unable to update trust for hash rule with hash $PrimaryKeyPart1 for policy $PolicyID ."
                    }
                }

                if (-not (Update-WDACTrustPoliciesAndComment -PrimaryKey1 $PrimaryKeyPart1 -Level "Hash" -Block $Block.ToBool() -PolicyGUID $PolicyID -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
                    throw "Could not update policy GUID and / or comment for this new hash rule."
                }
            }
            "Publisher" {
                foreach ($Result in ((Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -Level "Publisher" -UserMode $TrustedUserMode.ToBool() -Driver $TrustedDriver.ToBool() -Block $Block.ToBool() -Connection $Connection -ErrorAction Stop))) {
                    if (-not $Result) {
                        throw "Unable to update trust for publisher rule with publisher index $PrimaryKeyPart1 for policy $PolicyID ."
                    }
                }

                if (-not (Update-WDACTrustPoliciesAndComment -PrimaryKey1 $PrimaryKeyPart1 -Level "Publisher" -Block $Block.ToBool() -PolicyGUID $PolicyID -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
                    throw "Could not update policy GUID and / or comment for this new publisher rule."
                }
            }
            "FilePublisher" {
                $NewVersionNumber = New-WDACFilePublisherByCriteria -FileName $PrimaryKeyPart2 -PublisherIndex $PrimaryKeyPart1 -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -PolicyID $PolicyID -CurrentVersionNum $CurrentVersionNum -IsBlocking:$Block -Comment $Comment -Connection $Connection -ErrorAction Stop
            
                if (-not (Test-ValidVersionNumber -VersionNumber $NewVersionNumber)) {
                    throw "$NewVersionNumber is not a valid version number. Please reach out to the developer to fix this issue."
                }

                foreach ($Result in ((Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -PrimaryKey2 $PrimaryKeyPart2 -PrimaryKey3 $NewVersionNumber -Level "FilePublisher" -UserMode $TrustedUserMode.ToBool() -Driver $TrustedDriver.ToBool() -Block $Block.ToBool() -Connection $Connection -ErrorAction Stop))) {
                    if (-not $Result) {
                        throw "Unable to update trust for FilePublisher rule with PublisherIndex $PrimaryKeyPart1 and FileName $PrimaryKeyPart2 and MinimumFileVersion $CurrentVersionNum for policy $PolicyID ."
                    }
                }
            }
            "LeafCertificate" {
                foreach ($Result in ((Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -Level "LeafCertificate" -UserMode $TrustedUserMode.ToBool() -Driver $TrustedDriver.ToBool() -Block $Block.ToBool() -Connection $Connection -ErrorAction Stop))) {
                    if (-not $Result) {
                        throw "Unable to update trust for LeafCertificate rule with TBSHash $PrimaryKeyPart1 for policy $PolicyID ."
                    }
                }

                if (-not (Update-WDACTrustPoliciesAndComment -PrimaryKey1 $PrimaryKeyPart1 -Level "LeafCertificate" -Block $Block.ToBool() -PolicyGUID $PolicyID -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
                    throw "Could not update policy GUID and / or comment for this new LeafCertificate rule."
                }
            }
            "PcaCertificate" {
                foreach ($Result in ((Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -Level "PcaCertificate" -UserMode $TrustedUserMode.ToBool() -Driver $TrustedDriver.ToBool() -Block $Block.ToBool() -Connection $Connection -ErrorAction Stop))) {
                    if (-not $Result) {
                        throw "Unable to update trust for PcaCertificate rule with TBSHash $PrimaryKeyPart1 for policy $PolicyID ."
                    }
                }

                if (-not (Update-WDACTrustPoliciesAndComment -PrimaryKey1 $PrimaryKeyPart1 -Level "PcaCertificate" -Block $Block.ToBool() -PolicyGUID $PolicyID -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
                    throw "Could not update policy GUID and / or comment for this new PcaCertificate rule."
                }
            }
            "FilePath" {
                #TODO
            }
            "FileName" {
                $FileNameRule = Get-WDACFileName -FileName $PrimaryKeyPart1 -Connection $Connection -ErrorAction Stop
                if ($null -eq $FileNameRule) {
                    if (-not (Add-WDACFileName -FileName $PrimaryKeyPart1 -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to add new FileName entry to the trust database."
                    }
                }

                foreach ($Result in ((Update-WDACTrust -PrimaryKey1 $PrimaryKeyPart1 -Level "FileName" -UserMode $TrustedUserMode.ToBool() -Driver $TrustedDriver.ToBool() -Block $Block.ToBool() -Connection $Connection -ErrorAction Stop))) {
                    if (-not $Result) {
                        throw "Unable to update trust for FileName rule with name $PrimaryKeyPart1 and SpecificFileNameLevel $SpecificFileNameLevel for policy $PolicyID ."
                    }
                }

                if (-not (Update-WDACTrustPoliciesAndComment -PrimaryKey1 $PrimaryKeyPart1 -Level "FileName" -Block $Block.ToBool() -PolicyGUID $PolicyID -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
                    throw "Could not update policy GUID and / or comment for this new FileName rule."
                }
            }
        }

    } catch {
        throw $_
    }
}

function Restore-ProvidedLevelsOrder {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Levels,
        [Alias("OriginalLevels")]
        $ProvidedLevels
    )

    if (-not $ProvidedLevels) {
        return $Levels
    } else {
        $Result = @()
        foreach ($Level in $ProvidedLevels) {
            if ($Levels -contains $Level) {
                $Result += $Level
            }
        }
        return $Result
    }
}

function Get-ChosenPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt,
        $PolicyList,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $AllPolicyInfo = $null

        if ($PolicyList) {
            $AllPolicyInfo = Get-AllWDACPoliciesAndAllInfo -Connection $Connection -ErrorAction Stop | Where-Object {$PolicyList -contains $_.PolicyGUID}
        } else {
            $AnyAssignments = $false
            $GroupNames = Get-WDACGroups -Connection $Connection -ErrorAction Stop
            $GroupsWithAssignments = @()
            foreach ($Group in $GroupNames) {
                if ($null -ne (Get-WDACPolicyAssignments -GroupName $Group.GroupName -Connection $Connection -ErrorAction Stop)) {
                    $AnyAssignments = $true
                    $GroupsWithAssignments += $Group.GroupName
                }
            }

            if ($AnyAssignments) {
            #Since some policies have been assigned by group, we'll have the user filter by group first
                $SelectedGroup = Read-Host "Select a policy to assign trust--by first selecting a group that has policies assigned: ($(($GroupsWithAssignments -join ",")))"
                While (-not ($GroupsWithAssignments -contains $SelectedGroup)) {
                    $SelectedGroup = Read-Host "Please choose a group that has policies assigned: ($(($GroupsWithAssignments -join ",")))"
                }

                $GroupAssignments = Get-WDACPolicyAssignments -GroupName $SelectedGroup -Connection $Connection -ErrorAction Stop
                $PolicyList = @()
                foreach ($GroupAssignment in $GroupAssignments) {
                    $PolicyList += $GroupAssignment.PolicyGUID
                }

                $AllPolicyInfo = Get-AllWDACPoliciesAndAllInfo -Connection $Connection -ErrorAction Stop | Where-Object {$PolicyList -contains $_.PolicyGUID}

            } else {
                $AllPolicyInfo = Get-AllWDACPoliciesAndAllInfo -Connection $Connection -ErrorAction Stop
            }
        }

        Write-Host $Prompt
        $IndexCounter = 0
        foreach ($PolicyObject in $AllPolicyInfo) {
            $PolicyObject | Add-Member -NotePropertyName PolicyIndex -NotePropertyValue $IndexCounter
            $IndexCounter += 1
        }
        $AllPolicyInfo | Select-Object PolicyIndex,PolicyGUID,PolicyID,PolicyName,PolicyVersion | Out-Host
        $IndexSelection = Read-Host -Prompt "PolicyIndex Number"
        while ($null -eq (($AllPolicyInfo | Where-Object {$_.PolicyIndex -eq $IndexSelection} | Select-Object PolicyIndex).PolicyIndex)) {
            $IndexSelection = Read-Host -Prompt "Please Select an actual PolicyIndex"
        }
        return (($AllPolicyInfo | Where-Object {$_.PolicyIndex -eq $IndexSelection} | Select-Object PolicyGUID).PolicyGUID)

    } catch {
        throw $_
    }
    
}

function Get-ChosenSigningScenario {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $UserModeAppTrustLevels,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $KernelModeAppTrustLevels
    )

    Write-Host ($Prompt + " (UserMode / Driver / Both / U (Show User Mode Trust for this App) / K or D (Show Kernel mode Trust for this App) ): ")
    while ($true) {
        $InputString = Read-Host -Prompt "Option Selection"
        if ($InputString.ToLower() -eq "usermode") {
            return "UserMode"
        } elseif ($InputString.ToLower() -eq "driver") {
            return "Driver"
        } elseif ($InputString.ToLower() -eq "both") {
            return "Both"
        } elseif ($InputString.ToLower() -eq "k" -or $InputString.ToLower() -eq "d") {
            $KernelModeAppTrustLevels | Out-Host
        } elseif ($InputString.ToLower() -eq "u") {
            $UserModeAppTrustLevels | Out-Host
        } else {
            Write-Host "Not a valid option. Please supply UserMode or Driver (Additional Options: U (Show User Mode Trust for this App) / K or D (Show Kernel mode Trust for this App))."
        }
    }
}

function Read-WDACConferredTrust {
#NOTE: This function also adds File Publishers to the database!

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SHA256FlatHash,
        [switch]$RequireComment,
        $Levels,
        $GroupName,
        $PolicyName,
        $PolicyGUID,
        $PolicyID,
        [switch]$OverrideUserorKernelDefaults,
        $VersioningType,
        [switch]$ApplyVersioningToEntirePolicy,
        [switch]$MultiRuleMode,
        [switch]$ApplyRuleEachSigner,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $AppInfo = Get-WDACApp -Sha256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        $CertInfoAndMisc = Expand-WDACAppV2 -SHA256FlatHash $SHA256FlatHash -Levels $Levels -GetCerts -Connection $Connection -ErrorAction Stop
        $AppTrustLevels = Get-AppTrustedAllLevels -SHA256FlatHash $SHA256FlatHash -Driver:($AppInfo.SigningScenario -eq "Driver") -UserMode:($AppInfo.SigningScenario -eq "UserMode") -Connection $Connection -ErrorAction Stop
        $FileName = ($AppInfo.FirstDetectedPath + $AppInfo.FileName)

        if ( (-not $CertInfoAndMisc.CertsAndPublishers) -and $Levels) {
        #If this app has no signers
            $Levels = $Levels | Where-Object {$_ -ne "LeafCertificate"}
            $Levels = $Levels | Where-Object {$_ -ne "PcaCertificate"}
            $Levels = $Levels | Where-Object {$_ -ne "Publisher"}
            $Levels = $Levels | Where-Object {$_ -ne "FilePublisher"}

            if ((-not $Levels) -or $Levels.Count -le 0) {
                Write-Verbose "Cannot trust app $FileName (Hash $SHA256FlatHash) at the specified levels. Skipping."
                $AppsToSkip.Add($SHA256FlatHash,$true)
                Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null
                return;
            }
        }

        if (-not ($AppInfo.FileVersion) -and $Levels) {
            $Levels = $Levels | Where-Object {$_ -ne "FilePublisher"}

            if ((-not $Levels) -or $Levels.Count -le 0) {
                Write-Verbose "Cannot trust app $FileName (Hash $SHA256FlatHash) at the specified levels. Skipping."
                $AppsToSkip.Add($SHA256FlatHash,$true)
                Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null
                return;
            }
        }

        $SpecificFileNameLevelList = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")
        $ResultingSpecificFileNameLevelList = @()
        foreach ($FileNameLevel in $SpecificFileNameLevelList) {
            if (($AppInfo.$($FileNameLevel))) {
                $ResultingSpecificFileNameLevelList += $FileNameLevel
            }
        }
        if ($ResultingSpecificFileNameLevelList.Count -le 0 -and $Levels) {
            $Levels = $Levels | Where-Object {$_ -ne "FileName"}
            $Levels = $Levels | Where-Object {$_ -ne "FilePublisher"}

            if ((-not $Levels) -or $Levels.Count -le 0) {
                Write-Verbose "Cannot trust app $FileName (Hash $SHA256FlatHash ) at the specified levels. Skipping."
                $AppsToSkip.Add($SHA256FlatHash,$true)
                Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null
                return;
            }
        }
        ### DO YOU TRUST IT? #######################################################
        
        $IsTrusted = Get-WDACConferredTrust -Prompt "Do you trust the app $FileName with SHA256 Flat Hash $SHA256FlatHash ?" -AppInfo $AppInfo -CertInfoAndMisc $CertInfoAndMisc.CertsAndPublishers -AppTrustLevels $AppTrustLevels -SpecificFileNameLevelList $ResultingSpecificFileNameLevelList
        if ($AppsToSkip[$SHA256FlatHash]) {
            Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null
            return;
        } elseif (-not $IsTrusted -and -not $AppsToBlock[$SHA256FlatHash]) {
        #This case handles when a user selects "N", meaning they don't trust the app
            Write-WDACConferredTrust -PrimaryKeyPart1 $SHA256FlatHash -PrimaryKeyPart2 "Nonce" -Untrusted -Comment $AppComments[$SHA256FlatHash] -SpecificFileNameLevel "OriginalFileName" -Level "Hash" -Connection $Connection
            return;
        }
        
        ############################################################################
        

        ### HOW DO YOU TRUST IT? (AT WHAT LEVEL) ###################################
        $LevelToTrustAt = $null
        if ($Levels -and $MultiRuleMode -and ($Levels.Count -gt 1)) {
            $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?" -Levels $Levels
        } elseif (-not $Levels) {
            if (-not $CertInfoAndMisc.CertsAndPublishers) {
            #The case that there are no associated signers for this app
                if ($ResultingSpecificFileNameLevelList.Count -le 0) {
                    $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?" -Levels (@("Hash","FilePath"))
                } else {
                    $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?" -Levels (@("Hash","FilePath","FileName"))
                }
            } else {
                if ($ResultingSpecificFileNameLevelList.Count -le 0) {
                    $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?" -Levels (@("Hash","FilePath","LeafCertificate","PcaCertificate","Publisher"))
                } else {
                    if ($AppInfo.FileVersion) {
                        $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?"
                    } else {
                        $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?" -Levels (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher"))
                    }
                }
            }
        } elseif ($Levels.Count -gt 1) {
            foreach ($Level in $Levels) {
            #I'm not even sure that this for loop is necessary, might delete it later and replace with $LevelToTrustAt = $Levels[0]
                if ($AppTrustLevels.$($Level) -eq $false) {
                    $LevelToTrustAt = $Level;
                    break;
                } 
            }
        } else {
        #The case that there is only one level
            $LevelToTrustAt = $Levels[0]
            if ($MultiRuleMode) {
                if (-not (Get-YesOrNoPrompt -Prompt "Would you like to set this Trust (OR BLOCK) action at the level of $LevelToTrustAt ?")) {
                    $AppsToSkip.Add($SHA256FlatHash,$true)
                    Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null
                    return;
                }
            }
        }

        if ($LevelToTrustAt -eq "FilePath") {
            #Wittle-down the FilePath rule however the user wants
            #TODO: Implement a function to narrow down the FilePath rule however the user wants
        }
        ############################################################################################################


        ### WHICH SIGNER IS APPLIED THIS TRUST? (WHEN APPLICABLE) ##################################################
        $RuleSignerMapping = $null
        if (@("Publisher","FilePublisher","LeafCertificate","PcaCertificate") -contains $LevelToTrustAt) {
            if ($ApplyRuleEachSigner) {
                $RuleSignerMapping = "a"
            } else {
                if ((($CertInfoAndMisc.CertsAndPublishers | Select-Object SignatureIndex).SignatureIndex).Count -gt 1) {
                    $RuleSignerMapping = Get-RuleToSignerMapping -Signers $CertInfoAndMisc.CertsAndPublishers -Prompt "Which signer would you like to apply a rule of $LevelToTrustAt to?"
                } else {
                    $RuleSignerMapping = ($CertInfoAndMisc.CertsAndPublishers[0] | Select-Object SignatureIndex).SignatureIndex
                }
            }
        }
        ############################################################################################################

        $ResultantPolicies = @()
        $PolicyToApplyRuleTo = $null
        ### HOW DO YOU TRUST IT? (TRUSTED FOR WHAT POLICY) #########################################################
        if ($GroupName) {
            $PolicyAssignments = Get-WDACPolicyAssignments -GroupName $GroupName -Connection $Connection -ErrorAction Stop | Select-Object PolicyGUID
            foreach ($PolicyGUIDInstance in $PolicyAssignments) {
                $ResultantPolicies += $PolicyGUIDInstance.PolicyGUID
            }
        }
        if ($PolicyGUID) {
            foreach ($TempPolicyGUID in $PolicyGUID) {
                $ResultantPolicies += $TempPolicyGUID
            }
        }
        if ($PolicyID) {
            foreach ($TempPolicyID in $PolicyID) {
                $PolicyInstances = Get-WDACPoliciesById -PolicyID $TempPolicyID -Connection $Connection -ErrorAction Stop | Select-Object PolicyGUID
                foreach ($PolicyInstance in $PolicyInstances) {
                    $ResultantPolicies += $PolicyInstance.PolicyGUID
                }
            }
        }
        if ($PolicyName) {
            foreach ($TempPolicyName in $PolicyName) {
                $PolicyInstance2 = Get-WDACPolicyByName -PolicyName $TempPolicyName -Connection $Connection -ErrorAction Stop | Select-Object PolicyGUID
                $ResultantPolicies += $PolicyInstance2.PolicyGUID
            }
        }

        if ($ResultantPolicies.Count -gt 1) {
            $PolicyToApplyRuleTo = Get-ChosenPolicy -PolicyList $ResultantPolicies -Prompt "`nWhat policy do you want to apply this new rule to?" -Connection $Connection
        } elseif ($ResultantPolicies.Count -eq 1) {
            $PolicyToApplyRuleTo = $ResultantPolicies[0]
            Write-Verbose "Rule will be applied to policy $PolicyToApplyRuleTo "
        } else {
            $PolicyToApplyRuleTo = Get-ChosenPolicy -Prompt "`nWhat policy do you want to apply this new rule to?" -Connection $Connection
        }
        ############################################################################################################
        
        if ($AppInfo.BlockingPolicyID -eq $PolicyToApplyRuleTo -and ($AppsToBlock[$SHA256FlatHash]) -and (-not $IsTrusted)) {
        #If the user wants an app to be blocked, but the app entry already had the BlockingPolicyID attribute, then we exit the function
            Write-Warning "The app is already blocked according to this policy. Skipping trust granting actions for this app and continuing script execution."
            $AppsToSkip.Add($SHA256FlatHash,$true)
            Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null
            return
        }

        ### DO WE TRUST IT AT USERMODE OR KERNEL MODE? #############################################################
        $SigningLevelToTrustRuleAt = $null
        $SigningScenario = $AppInfo.SigningScenario
        if ($LevelToTrustAt -eq "FilePath") {
        #FilePath rules can only be applied to user-mode binaries
            $SigningLevelToTrustRuleAt = "UserMode"
        } elseif ($OverrideUserorKernelDefaults) {
            $UserModeTrustLevels = Get-AppTrustedAllLevels -SHA256FlatHash $SHA256FlatHash -UserMode -Connection $Connection -ErrorAction Stop
            $KernelModeTrustLevels = Get-AppTrustedAllLevels -SHA256FlatHash $SHA256FlatHash -Driver -Connection $Connection -ErrorAction Stop
            $SigningLevelToTrustRuleAt = Get-ChosenSigningScenario -Prompt "What Signing level do you trust this application at?" -UserModeAppTrustLevels $UserModeTrustLevels -KernelModeAppTrustLevels $KernelModeTrustLevels
        } else {
            if ($SigningScenario -eq "UserMode") {
                $SigningLevelToTrustRuleAt = "UserMode"
            } elseif ($SigningScenario -eq "Driver") {
                $SigningLevelToTrustRuleAt = "Driver"
            } else {
                $SigningLevelToTrustRuleAt = "UserMode"
            }
        }
        ############################################################################################################

        ### GET COMMENT ############################################################################################
        $Comment = $null
        if ($AppComments[$SHA256FlatHash]) {
            $Comment = $AppComments[$SHA256FlatHash]
        } elseif ($RequireComment -and (-not $AppComments[$SHA256FlatHash])) {
            $Comment = Read-Host -Prompt "Enter your comment about this app"
        }
        ############################################################################################################

        $SpecificFileNameLevel = "OriginalFileName"
        if ($SpecificFileNameLevels[$SHA256FlatHash]) {
            $SpecificFileNameLevel = $SpecificFileNameLevels[$SHA256FlatHash]
        }

        if ((-not $SpecificFileNameLevels[$SHA256FlatHash]) -and $SpecificFileNameLevel -eq "OriginalFileName" -and (-not $AppInfo.OriginalFileName) -and ($LevelToTrustAt -eq "FilePublisher" -or $LevelToTrustAt -eq "FileName")) {
            Get-SpecificFileNameLevelPrompt -Levels $ResultingSpecificFileNameLevelList
        }

        $LeafCertCNs = @{}
        $LeafCertTBSHashes = @{}
        $PcaCertTBSHashes = @{}
        $Publishers = @{}

        if (@("Publisher","FilePublisher","LeafCertificate","PcaCertificate") -contains $LevelToTrustAt -and ($CertInfoAndMisc.CertsAndPublishers)) {
            foreach ($Signer in $CertInfoAndMisc.CertsAndPublishers) {
                $LeafCertCNs.Add($Signer.SignatureIndex,$Signer.LeafCert.CommonName)
                $LeafCertTBSHashes.Add($Signer.SignatureIndex,$Signer.LeafCert.TBSHash)
                $PcaCertTBSHashes.Add($Signer.SignatureIndex,$Signer.PcaCertificate.TBSHash)

                $PublisherIndex = (Get-WDACPublisher -LeafCertCN $Signer.LeafCert.CommonName -PcaCertTBSHash $Signer.PcaCertificate.TBSHash -Connection $Connection -ErrorAction Stop).PublisherIndex
                $Publishers.Add($Signer.SignatureIndex,$PublisherIndex)
            }
        }

        switch ($LevelToTrustAt) {
            "Hash" {
                Write-WDACConferredTrust -PrimaryKeyPart1 $SHA256FlatHash -PrimaryKeyPart2 "Nonce" -TrustedDriver:($SigningLevelToTrustRuleAt -eq "Driver" -or $SigningLevelToTrustRuleAt -eq "Both") -TrustedUserMode:($SigningLevelToTrustRuleAt -eq "UserMode" -or $SigningLevelToTrustRuleAt -eq "Both") -Block:($null -ne $AppsToBlock[$SHA256FlatHash]) -Comment $Comment -SpecificFileNameLevel $SpecificFileNameLevel -PolicyID $PolicyToApplyRuleTo -Level $LevelToTrustAt -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -Connection $Connection
            }
            "Publisher" {
                foreach ($Signer in $CertInfoAndMisc.CertsAndPublishers) {
                    if ($RuleSignerMapping -eq $Signer.SignatureIndex -or ($RuleSignerMapping -eq "a")) {
                        Write-WDACConferredTrust -PrimaryKeyPart1 $Publishers[$Signer.SignatureIndex] -PrimaryKeyPart2 "Nonce" -TrustedDriver:($SigningLevelToTrustRuleAt -eq "Driver" -or $SigningLevelToTrustRuleAt -eq "Both") -TrustedUserMode:($SigningLevelToTrustRuleAt -eq "UserMode" -or $SigningLevelToTrustRuleAt -eq "Both") -Block:($null -ne $AppsToBlock[$SHA256FlatHash]) -Comment $Comment -SpecificFileNameLevel $SpecificFileNameLevel -PolicyID $PolicyToApplyRuleTo -Level $LevelToTrustAt -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -Connection $Connection
                    }
                }
            }
            "FilePublisher" {
                foreach ($Signer in $CertInfoAndMisc.CertsAndPublishers) {
                    if (($RuleSignerMapping -eq $Signer.SignatureIndex) -or ($RuleSignerMapping -eq "a")) {
                        Write-WDACConferredTrust -PrimaryKeyPart1 $Publishers[$Signer.SignatureIndex] -PrimaryKeyPart2 $AppInfo.$($SpecificFileNameLevel) -TrustedDriver:($SigningLevelToTrustRuleAt -eq "Driver" -or $SigningLevelToTrustRuleAt -eq "Both") -TrustedUserMode:($SigningLevelToTrustRuleAt -eq "UserMode" -or $SigningLevelToTrustRuleAt -eq "Both") -Block:($null -ne $AppsToBlock[$SHA256FlatHash]) -Comment $Comment -SpecificFileNameLevel $SpecificFileNameLevel -PolicyID $PolicyToApplyRuleTo -Level $LevelToTrustAt -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -CurrentVersionNum $AppInfo.FileVersion -Connection $Connection
                    }
                }
            }
            "LeafCertificate" {
                foreach ($Signer in $CertInfoAndMisc.CertsAndPublishers) {
                    if ($RuleSignerMapping -eq $Signer.SignatureIndex -or ($RuleSignerMapping -eq "a")) {
                        Write-WDACConferredTrust -PrimaryKeyPart1 $LeafCertTBSHashes[$Signer.SignatureIndex] -PrimaryKeyPart2 "Nonce" -TrustedDriver:($SigningLevelToTrustRuleAt -eq "Driver" -or $SigningLevelToTrustRuleAt -eq "Both") -TrustedUserMode:($SigningLevelToTrustRuleAt -eq "UserMode" -or $SigningLevelToTrustRuleAt -eq "Both") -Block:($null -ne $AppsToBlock[$SHA256FlatHash]) -Comment $Comment -SpecificFileNameLevel $SpecificFileNameLevel -PolicyID $PolicyToApplyRuleTo -Level $LevelToTrustAt -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -Connection $Connection
                    }
                }
            }
            "PcaCertificate" {
                foreach ($Signer in $CertInfoAndMisc.CertsAndPublishers) {
                    if ($RuleSignerMapping -eq $Signer.SignatureIndex -or ($RuleSignerMapping -eq "a")) {
                        Write-WDACConferredTrust -PrimaryKeyPart1 $PcaCertTBSHashes[$Signer.SignatureIndex] -PrimaryKeyPart2 "Nonce" -TrustedDriver:($SigningLevelToTrustRuleAt -eq "Driver" -or $SigningLevelToTrustRuleAt -eq "Both") -TrustedUserMode:($SigningLevelToTrustRuleAt -eq "UserMode" -or $SigningLevelToTrustRuleAt -eq "Both") -Block:($null -ne $AppsToBlock[$SHA256FlatHash]) -Comment $Comment -SpecificFileNameLevel $SpecificFileNameLevel -PolicyID $PolicyToApplyRuleTo -Level $LevelToTrustAt -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -Connection $Connection
                    }
                }
            }
            "FilePath" {
                #TODO
                Write-Verbose "FilePath rules have not yet been implemented."
            }
            "FileName" {
                Write-WDACConferredTrust -PrimaryKeyPart1 $AppInfo.$($SpecificFileNameLevel) -PrimaryKeyPart2 "Nonce" -TrustedDriver:($SigningLevelToTrustRuleAt -eq "Driver" -or $SigningLevelToTrustRuleAt -eq "Both") -TrustedUserMode:($SigningLevelToTrustRuleAt -eq "UserMode" -or $SigningLevelToTrustRuleAt -eq "Both") -Block:($null -ne $AppsToBlock[$SHA256FlatHash]) -Comment $Comment -SpecificFileNameLevel $SpecificFileNameLevel -PolicyID $PolicyToApplyRuleTo -Level $LevelToTrustAt -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -Connection $Connection
            }
        }

        $AppsToSkip.Add($SHA256FlatHash,$true)
        Set-WDACSkipped -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction SilentlyContinue | Out-Null

        if (($LevelToTrustAt.ToLower() -ne "hash") -and ($AppTrustLevels.Hash -eq $false)) {
        #The apps table is used to represent hash rules, so they are not purged from the database right now
            $AppsToPurge.Add($SHA256FlatHash,$true)
        }

    } catch {
        throw $_
    }
}

function Approve-WDACRules {
    <#
    .SYNOPSIS
    Iterate over events from pipeline--or from particular rows in the apps table if no pipeline input--and prompt user whether they trust the given apps at the provided level.

    .DESCRIPTION
    For each inputted event--or for each event in the apps table which is not specifically blocked or revoked--give the code integrity event to a dialogue box
    which will ask the user HOW they wish to trust the event; this includes at what level to trust the event (file publisher, file hash, publisher etc.) as 
    well as what specific policy to attach the trust with (which is granularized by whether the user provided a policyname, policyGUID, or policyid to this commandlet.)
    (A user may specify these items with params so they are not prompted to provide this information.)
    A user may trust a file publisher for one policy, but only trust at the level of a file hash for another policy.
    Then, the "trusted" variable in the trust database will be set (using Sqlite connection) for the provided levels.
    A user may also specify whether to trust at the kernel or usermode levels (overriding the information provided in the event, i.e., "UserMode" or "Driver").
    NOTE: This cmdlet is also when publishers and file_publishers are added to their respective tables in the database. Any hash rules on the other hand, will be trusted on the "apps" table. (Which are already in the database at this point.)
    NOTE: The version numbers that are associated with file publisher rules are governed by the VersioningType parameter.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER Events
    Pipeline input of WDAC events which are piped from Register-WDACEvents

    .PARAMETER RequireComment
    When this is set, a comment must be provided when an app is trusted.

    .PARAMETER Purge
    When set, this will allow apps (i.e., audit events) to be deleted from the apps table when a considered app is trusted at a higher level (such as publisher or file publisher).
    Will not delete an audit event when it is used to set a File Hash or File Path rule.

    .PARAMETER Level
    What rule level you want to first consider trust at. (If not provided, the dialogue box will prompt the user.)
    Supported levels: Hash, Publisher, FilePublisher, LeafCertificate, PcaCertificate, FilePath (only applies to user-mode binaries), or FileName (not recommended for allow rules).
    
    .PARAMETER Fallbacks
    What backup rule levels to apply trust at if needed. See "Level". (If not provided, the dialogue box will NOT prompt the user for fallbacks.)

    .PARAMETER GroupName
    When this is provided, policies linked with this particular group will be considered for linking trust.

    .PARAMETER PolicyName
    When this is provided, the policy (or policies) associated with that name(s) will be considered for linking trust.

    .PARAMETER PolicyGUID
    When this is provided, this policy (or policies) will be considered for linking trust.

    .PARAMETER PolicyID
    When this is provided, policies which match this provided PolicyID (or PolicyIDs) will be considered for linking trust.

    .PARAMETER OverrideUserorKernelDefaults
    This overrides the default behavior of looking at SigningScenario (for the words "Driver" or "UserMode") when deciding to trust on User Mode or Kernel Mode
    This also overrides the behavior of trusting only on UserMode by default if no SigningScenario is present.
    Instead, the user will be prompted whether to trust the app at the level of kernel mode or user mode.

    .PARAMETER VersioningType
    OPTIONAL: Supply an integer for different versioning behavior for file publishers. These will be written to the database (as publisher index + file name combinations)
    NOTE: VersioningType only applies to Trust actions, not "Block" actions
    NOTE: VersioningTypes are written to the database when specified with this parameter (or the parameter AlwaysSetMinimumVersions is set)
    NOTE: Options 0-5 deal with the "file_publisher_options" table, options 6-11 deal with the "policy_file_publisher_options" table
        policy_file_publisher_options has priority over file_publisher_options

        0 - GLOBAL SET MINIMUM - For a particular publisher index + file name combination, prompt the user for a [fixed] MinimumFileVersion that will be applied anytime the combination appears (applied to ALL policies)
        1 - GLOBAL DECREMENT MINIMUM - For a particular publisher index + file name combination, replace the MinimumFileVersion with a new one anytime a lower one appears for all appearances of the combination
        2 - GLOBAL ALWAYS SPECIFY - Anytime a new FileVersion is encountered for a publisher index + file name combination, prompt the user whether they want to change the MinimumFileVersion (applied to this combination for ALL policies)
        3 - GLOBAL INCREMENT MINIMUM - For a particular publisher index + file name combination, replace the MinimumFileVersion with a new one anytime a GREATER one appears for all appearances of the combination
        4 - GLOBAL 0.0.0.0 MINIMUM - Exactly like option 0, but 0.0.0.0 will always be set to be the MinimumFileVersion without prompting the user
        5 - GLOBAL DECREMENT MINIMUM NOT EXCEEDING MINIMUM_TOLERABLE_MINIMUM - Similar to option 1, but each time the MinimumFileVersion is replaced with a lower encountered file version, it cannot go lower than a MinimumTolerableMinimum specified by the user.
        6 - EACH POLICY SET MINIMUM - Prompt the user whether they want a [fixed] MinimumFileVersion for each time a new publisher index + file name combination is encountered for each individual policy. 
        7 - EACH POLICY DECREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a lower one anytime a lower one is encountered
        8 - EACH POLICY ALWAYS SPECIFY - Similar to option 2, but anytime a new publisher index + file name combination is encountered for EACH POLICY, the user will be prompted if they want to change the MinimumFileVersion
        9 - EACH POLICY INCREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a HIGHER one anytime a higher one is encountered
        10 - EACH POLICY 0.0.0.0 Minimum - Exactly like option 6, but the MinimumFileVersion will always be set to 0.0.0.0 without prompting the user
        11 - EACH POLICY DECREMENT MINIMUM NOT EXCEEDING MINIMUM_TOLERABLE_MINIMUM - Similar to option 7, but each time the MinimumFileVersion is replaced with a lower encountered file version, it cannot go lower than a MinimumTolerableMinimum specified by the user (which must be specified for each policy)

    .PARAMETER IgnoreErrors
    Do not terminate the function based on error count--and ignore the all-or-nothing behavior of updating trust in the database.
    NOTE: There is no all-or-nothing behavior when events are piped into the cmdlet instead of pulled from the database!

    .PARAMETER MSIorScripts
    Pull events with no trust action from the msi_or_script table instead of the apps table.

    .PARAMETER ModifyUniversalVersioning
    Modify the GlobalVersioningType in Resources/LocalStorage.json to reflect that value provided by VersioningType
    NOTE: This VersioningType will be applied to ANY file publisher rule imaginable -- until the value is set back to an empty string "".

    .PARAMETER ApplyVersioningTypeToEntirePolicy
    When a VersioningType is specified with VersioningType, and each time a new policy is encountered, the VersioningType is written to the policy_versioning_options table.
    This means that the VersioningType will be applied to all file name + publisher index combinations for the entire policy IF NOT ALREADY SET EXPLICITLY.

    .PARAMETER MultiRuleMode
    Even if an app is already trusted at the specified levels, this option allows you to check to see if you can allow the app at another level--for example, 
    if a file publisher is allowed for one policy and allows an app to run, you can still allow an app by hash for another policy. 
    (This will prompt the user whether they want to allow the other rule.) Can only be set when Level AND fallbacks are specified. 

    .PARAMETER ResetUntrusted
    Reset the untrusted flag for every "untrusted" app in the database (this doesn't reset flags for blocked or revoked)

    .PARAMETER ApplyRuleEachSigner
    When this flag is set, anytime the user specifies that they want a WDAC rule level involving a certificate -- such a rule will be created for each signer automatically without prompting the user.
    (Applies to PcaCertificate, LeafCertificate, Publisher, and FilePublisher rules)

    .INPUTS
    [PSCustomObject] Result of Register-WDACEvents (OPTIONAL)

    .OUTPUTS
    Nothing.

    .EXAMPLE
    TODO: EXAMPLES!

    .EXAMPLE
    TODO: EXAMPLES!

    .EXAMPLE
    TODO: EXAMPLES!

    .EXAMPLE
    TODO: EXAMPLES!
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [PSCustomObject[]]$Events,
        [switch]$RequireComment,
        [switch]$Purge,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string]$Level,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Fallbacks,
        [string]$GroupName,
        [string[]]$PolicyName,
        [string[]]$PolicyGUID,
        [string[]]$PolicyID,
        [Alias("NoDefault","Override")]
        [switch]$OverrideUserorKernelDefaults,
        [ValidateSet(0,1,2,3,4,5,6,7,8,9,10,11)]
        $VersioningType,
        [Alias("Ignore")]
        [switch]$IgnoreErrors,
        [Alias("MSI","Script","MSIorScript")]
        [switch]$MSIorScripts,
        [Alias("UniversalVersioning","UniversalReset")]
        [switch]$ModifyUniversalVersioning,
        [Alias("EachPolicyVersioning","PolicyVersioning","ApplyEntirePolicy")]
        [switch]$ApplyVersioningToEntirePolicy,
        [Alias("MultiMode","MultiLevel","MultiLevelMode")]
        [switch]$MultiRuleMode,
        [Alias("Reset")]
        [switch]$ResetUntrusted,
        [switch]$ApplyRuleEachSigner
    )

    begin {
        if ($Fallbacks -and -not $Level) {
            throw "Cannot provide fallbacks without providing a level. (This would be the preferred or default level.)"
        }

        if ($ModifyUniversalVersioning -and -not $VersioningType) {
            throw "When ModifyUniversalVersioning is set, a VersioningType must also be provided."
        }

        if ((($GroupName) -and ($PolicyName -or $PolicyGUID -or $PolicyID)) -or (($PolicyName) -and ($GroupName -or $PolicyGUID -or $PolicyID)) -or (($PolicyGUID) -and ($GroupName -or $PolicyName -or $PolicyID)) -or (($PolicyID) -and ($GroupName -or $PolicyGUID -or $PolicyName))) {
            Write-Warning "When more than of these options (GroupName, PolicyName, PolicyGUID, or PolicyID) are selected, the user will be prompted to select which policy a rule should be applied to."
        }

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
    }

    process {
        $HasPipelineInput = $false
        if ($Events) {
            $HasPipelineInput = $true
        }

        if (-not $HasPipelineInput) {
            #This clears all the "Skipped" properties on apps and msi_or_script so they are all 0
            #If there is pipeline input, using Clear-AllWDACSkipped will clear Skipped property prematurely (since Register-WDACEvents is a filter function).
            #...So only run this block of code if there is NO pipeline input
            try {
                Clear-AllWDACSkipped -ErrorAction Stop
            } catch {
                Write-Verbose $_
                throw "Could not clear all the `"Skipped`" properties on apps and scripts. Clear attribute manually before running Approve-WDACRules again."
            }
        }
        
        try {
            if ($GroupName) {
                if (-not (Get-WDACPolicyAssignments -GroupName $GroupName -ErrorAction Stop)) {
                    throw "There are no policies assigned to this group name. Please assign policies to a group using the Register-WDACGroup cmdlet."
                }
            }
            if ($PolicyName) {
                foreach ($TempPolicyName in $PolicyName) {
                    if (-not (Find-WDACPolicyByName -PolicyName $TempPolicyName -ErrorAction Stop)) {
                        throw "There are no policies by this policy name: $TempPolicyName in the database."
                    }
                }
            }
            if ($PolicyGUID) {
                foreach ($TempPolicyGUID in $PolicyGUID) {
                    if (-not (Find-WDACPolicy -PolicyGUID $TempPolicyGUID -ErrorAction Stop)) {
                        throw "There are no policies in the database with this GUID: $TempPolicyGUID ."
                    }
                }
            }
            if ($PolicyID) {
                foreach ($TempPolicyID in $PolicyID) {
                    if (-not (Find-WDACPolicyByID -PolicyID $TempPolicyID -ErrorAction Stop)) {
                        throw "There are no policies with ID $TempPolicyID in the database. It's worth noting that PolicyID is NOT the same as PolicyGUID."
                    }
                }
            }
        } catch {
            throw $_
        }

        if ($ModifyUniversalVersioning) {
            try {
                Set-ValueLocalStorageJSON -Key "GlobalVersioningType" -Value $VersioningType -ErrorAction Stop
            } catch {
                Write-Warning "Unable to update cached VersioningType value in LocalStorage.json."
            }
        }

        try {
            $TempVersioningNum = (Get-LocalStorageJSON -ErrorAction Stop)."GlobalVersioningType"
            if ($TempVersioningNum -and -not $VersioningType) {
            #GlobalVersioningType is only used if the user hasn't specifically specified one when running the cmdlet
                $VersioningType = $TempVersioningNum
            }
        } catch {
            Write-Warning "Unable to retrieve GlobalVersioningType from LocalStorage.json."
        }

        $ErrorCount = 0
        if (-not $Events) {
            try {
                if ($MSIorScripts) {
                    #TODO
                } else {
                    $Events = Get-WDACAppsToSetTrust -ErrorAction Stop
                }
            } catch {
                throw $_
            }
        } elseif ($MSIorScripts) {
            Write-Warning "MSIorScripts parameter ignored since events are being piped into this cmdlet."
        }
     
        try {
            $Connection = New-SQLiteConnection -ErrorAction Stop

            foreach ($Event in $Events) {

                $Transaction = $Connection.BeginTransaction()

                if ($ErrorCount -ge 4 -and -not $IgnoreErrors) {
                    throw "Error count exceeding acceptable amount. Terminating."
                }

                try {
                    if ($Event.SHA256FileHash) {
                    #Case info is piped into the Approve-WDACRules cmdlet
                        $AppHash = $Event.SHA256FileHash
                        $FileName = $Event.FilePath
                    } else {
                    #Case info if retrieved from the database
                        $AppHash = $Event.SHA256FlatHash
                        $FileName = $Event.FileName
                    }
                    
                    if ($AppsToSkip[$AppHash] -or $AppsToBlock[$AppHash]) {
                    #User already designated that they want to skip this app for this session
                        $Transaction.Rollback()
                        continue;
                    }

                    if (-not (Find-WDACApp -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop)) {
                    #Even if the app is piped into the cmdlet it still has to exist in the database.
                        if (-not ($AppsToSkip[$AppHash])) {
                            $AppsToSkip.Add($AppHash,$true)
                        }
                        $Transaction.Rollback()
                        continue;
                    }

                    if ((Get-WDACAppUntrustedStatus -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop)) {
                    #Case the user has already set an untrust action on this app
                        if (-not ($AppsToSkip[$AppHash])) {
                            $AppsToSkip.Add($AppHash,$true)
                        }
                        $Transaction.Rollback()
                        continue;
                    }

                    if ( (Get-MSIorScriptSkippedStatus -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction SilentlyContinue) -or (Get-WDACAppSkippedStatus -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction SilentlyContinue)) {
                        if (-not ($AppsToSkip[$AppHash])) {
                            $AppsToSkip.Add($AppHash,$true)
                        }
                        $Transaction.Rollback()
                        continue;
                    }

                    if (Test-AppBlocked -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction SilentlyContinue) {
                        if (-not ($AppsToSkip[$AppHash])) {
                            $AppsToSkip.Add($AppHash,$true)
                        }
                        $Transaction.Rollback()
                        continue;
                    }

                    ########TODO: Update file versions in this main loop if the file publisher is already trusted

                    $Transaction.Commit()
                    #This commit() statement is so that changes made by Update-WDACFilePublisherByCriteria can be applied regardless of whether a trust action is successfully made
                    $Transaction = $Connection.BeginTransaction()

                    $SigningScenario = $Event.SigningScenario
                    if ($SigningScenario) {
                        if ((Get-AppTrusted -SHA256FlatHash $AppHash -Driver:($SigningScenario -eq "Driver") -UserMode:($SigningScenario -eq "UserMode") -Connection $Connection -ErrorAction Stop)) {
                        #This indicates that the app is already trusted at a higher level (in general, not checking specifically, which is done in an if statement below)
                            
                            if ($AllLevels -and $MultiRuleMode -and $AllLevels.Count -ge 1) {
                                $MiscLevels = @()
                                $AppTrustAllLevels = ((Get-AppTrustedAllLevels -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop).PSObject.Properties | Where-Object {$_.Value -eq $false} | Select-Object Name).Name
                                $AppTrustAllLevels = Restore-ProvidedLevelsOrder -Levels $AppTrustAllLevels -ProvidedLevels $AllLevels
                                #^This restores the original order the user provided the levels and fallbacks
                                foreach ($AppTrustLevel in $AppTrustAllLevels) {
                                #This checks for if there are any remaining untrusted levels for which to use MultiRuleMode
                                    if ($AllLevels -and ($AllLevels -contains $AppTrustLevel)) {
                                        $MiscLevels += $AppTrustLevel
                                    } elseif (-not $AllLevels) {
                                        $MiscLevels += $AppTrustLevel
                                    }
                                }
                                if ($MiscLevels.Count -ge 1) {
                                    Write-Verbose "Multi-Rule Mode Initiated for this app: $FileName ";
                                    Read-WDACConferredTrust -SHA256FlatHash $AppHash -RequireComment:$RequireComment -Levels $MiscLevels -GroupName $GroupName -PolicyName $PolicyName -PolicyGUID $PolicyGUID -PolicyID $PolicyID -OverrideUserorKernelDefaults:$OverrideUserorKernelDefaults -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -MultiRuleMode -ApplyRuleEachSigner:$ApplyRuleEachSigner -Connection $Connection -ErrorAction Stop;
                                    $Transaction.Commit()
                                    continue;
                                }
                            }
                            if ((Get-AppTrusted -SHA256FlatHash $AppHash -Levels $AllLevels -Driver:($SigningScenario -eq "Driver") -UserMode:($SigningScenario -eq "UserMode") -Connection $Connection -ErrorAction Stop)) {
                            #The difference between this if statement and the one above is this one provides the AllLevels parameter
                                Write-Verbose "Skipping app which already satisfies a level of trust: $FileName with hash $AppHash"
                                $AppTrustAllLevels = Get-AppTrustedAllLevels -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop
                                if ((-not ($AppTrustAllLevels.Hash)) -and (-not $AppsToPurge[$AppHash])) {
                                    $AppsToPurge.Add($AppHash,$true)
                                }
                                if (-not ($AppsToSkip[$AppHash])) {
                                    $AppsToSkip.Add($AppHash,$true)
                                }
                                $Transaction.Rollback()
                                continue;
                            }
                        }
                    }

                    Read-WDACConferredTrust -SHA256FlatHash $AppHash -RequireComment:$RequireComment -Levels $AllLevels -GroupName $GroupName -PolicyName $PolicyName -PolicyGUID $PolicyGUID -PolicyID $PolicyID -OverrideUserorKernelDefaults:$OverrideUserorKernelDefaults -VersioningType $VersioningType -ApplyVersioningToEntirePolicy:$ApplyVersioningToEntirePolicy -ApplyRuleEachSigner:$ApplyRuleEachSigner -Connection $Connection -ErrorAction Stop

                } catch {
                    Write-Verbose $_
                    Write-Warning "Could not apply trust action to the database for this app: $($AppHash) ."
                    $Transaction.Rollback()
                    $ErrorCount += 1
                    continue
                }

                $Transaction.Commit()
            }

            if ($Purge) {
                foreach ($Event in $Events) {
                    $Transaction = $Connection.BeginTransaction()
                    if ($ErrorCount -ge 4 -and -not $IgnoreErrors) {
                        throw "Error count exceeding acceptable amount. Terminating."
                    }

                    try {
                        if ($Event.SHA256FileHash) {
                            #Case info is piped into the Approve-WDACRules cmdlet
                                $AppHash = $Event.SHA256FileHash
                            } else {
                            #Case info if retrieved from the database
                                $AppHash = $Event.SHA256FlatHash
                            }
                        if ($AppsToPurge[$AppHash]) {
                            Remove-WDACApp -Sha256FlatHash $AppHash -Connection $Connection -ErrorAction Stop
                        }
                    } catch {
                        Write-Verbose $_
                        Write-Warning "Could not purge this app from the database: $($AppHash) ."
                        $Transaction.Rollback()
                        $ErrorCount += 1
                        continue
                    }

                    $Transaction.Commit()
                }
            }

        } catch {
            $theError = $_
            if ($Transaction) {
                $Transaction.Rollback()
            }
            if ($Connection) {
                $Connection.Close()
            }

            if (-not $HasPipelineInput) {
                Write-Host "Successfully updated trust for those potential rules in the database. Use Merge-TrustedWDACRules to merge them into policies."
    
                try {
                #This clears all the "Skipped" properties on apps and msi_or_script so they are all 0 when Approve-WDACRules cmdlet is used again.
                #If there is pipeline input, using Clear-AllWDACSkipped will clear Skipped property prematurely (since Register-WDACEvents is a filter function).
                #...So only run this block of code if there is NO pipeline input
                    Clear-AllWDACSkipped -ErrorAction Stop
                } catch {
                    Write-Verbose $_
                    Write-Warning "Could not clear all the `"Skipped`" properties on apps and scripts. Clear attribute manually before running Approve-WDACRules again."
                }
            }
            
            throw $theError
        }

        $Connection.Close()
        Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue

        if (-not $HasPipelineInput) {
            Write-Host "Successfully updated trust for those potential rules in the database. Use Merge-TrustedWDACRules to merge them into policies."

            try {
            #This clears all the "Skipped" properties on apps and msi_or_script so they are all 0 when Approve-WDACRules cmdlet is used again.
            #If there is pipeline input, using Clear-AllWDACSkipped will clear Skipped property prematurely (since Register-WDACEvents is a filter function).
            #...So only run this block of code if there is NO pipeline input
                Clear-AllWDACSkipped -ErrorAction Stop
            } catch {
                Write-Verbose $_
                Write-Warning "Could not clear all the `"Skipped`" properties on apps and scripts. Clear attribute manually before running Approve-WDACRules again."
            }
        }
    }

    end {
        
    }
}