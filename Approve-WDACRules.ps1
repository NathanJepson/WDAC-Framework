$AppsToSkip = @{}
$AppsToBlock = @{}
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
        $InputString = Read-Host
        if (-not ($Levels -contains $InputString)) {
            Write-Host ("Not a valid option. Please supply one of these options: (" + ($Levels -join ",") + ")")
        } else {
            return $InputString
        }
    }
}

function Get-WDACConferredTrust {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt,
        $AppInfo,
        $CertInfoAndMisc,
        $AppTrustLevels
    )

    if ($AppTrustLevels) {
        foreach ($TrustLevel in $AppTrustLevels) {
            if ($TrustLevel.PSObject.Properties.Value) {
                Write-Warning "This app is already trusted at a separate rule level."
                break
            }
        }
    }

    $Options = "([Y] (Yes) [N] (NO) [S] (SKIP) [B] (BLOCK) [A or E] (Expand / View App Info) [C] (Expand / View Certificate + Publisher Info) [T] (View Trust for this App for Respective Rule Levels))"

    Write-Host ($Prompt + ": " + $Options)
    while ($true) {
        $InputString = Read-Host -Prompt "Option Selection"
        if ($InputString.ToLower() -eq "y") {
            return $true
        } elseif ($InputString.ToLower() -eq "n") {
            return $false
        } elseif ($InputString.ToLower() -eq "s") {
            $AppsToSkip.Add($AppInfo.SHA256FlatHash,$true)
            return $false
        } elseif ($InputString.ToLower() -eq "e" -or $InputString.ToLower() -eq "a") {
            $AppInfo | Out-Host
            Write-Host ("Options: " + $Options)
        }
        elseif ($InputString.ToLower() -eq "c") {
            foreach ($Signer in $CertInfoAndMisc) {
                $Signer | Select-Object SignatureIndex, SignerInfo, LeafCert, PcaCertificate | Format-List -Property * | Out-Host
            }
            Write-Host ("Options: " + $Options)
        }
        elseif ($InputString.ToLower() -eq "t") {
            $AppTrustLevels | Out-Host
            Write-Host ("Options: " + $Options)
        } elseif ($InputString.ToLower() -eq "b") {
            $AppsToBlock.Add($AppInfo.SHA256FlatHash,$true)
            return $false
        }
        else {
            Write-Host ("Not a valid option. Select one of these options: " + $Options)
        }
    }
}

function Write-WDACConferredTrust {
    [CmdletBinding()]
    Param (
        [string]$PrimaryKeyPart1,
        [string]$PrimaryKeyPart2,
        [bool]$Untrusted,
        [bool]$TrustedDriver,
        [bool]$TrustedUserMode,
        [string]$Comment,
        [string]$AllowedPolicyID,
        [string]$Level,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

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
        [ValidateSet(0,1,2,3,4,6,7,8,9,10,12,13,14,15,16)]
        $VersioningType,
        [switch]$AdvancedVersioning,
        [switch]$MultiRuleMode,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $AppInfo = Get-WDACApp -Sha256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        $CertInfoAndMisc = Expand-WDACAppV2 -SHA256FlatHash $SHA256FlatHash -Levels $Levels -GetCerts -Connection $Connection -ErrorAction Stop
        $AppTrustLevels = Get-AppTrustedAllLevels -SHA256FlatHash $AppHash -Driver:($AppInfo.SigningScenario -eq "Driver") -UserMode:($AppInfo.SigningScenario -eq "UserMode") -Connection $Connection -ErrorAction Stop
        $FileName = ($AppInfo.FirstDetectedPath + $AppInfo.FileName)

        ### DO YOU TRUST IT? #######################
        $IsTrusted = Get-WDACConferredTrust -Prompt "Do you trust the app $FileName with SHA256 Flat Hash $SHA256FlatHash ?" -AppInfo $AppInfo -CertInfoAndMisc $CertInfoAndMisc.CertsAndPublishers -AppTrustLevels $AppTrustLevels
        if ($AppsToSkip[$SHA256FlatHash]) {
            return;
        } elseif (-not $IsTrusted -and -not $AppsToBlock[$SHA256FlatHash]) {
        #This case handles when a user selects "N", meaning they don't trust the app

            #TODO: Set the "Untrusted" var in the database
            #TODO Write-WDACConferredTrust
            return;
        }
        ############################################

        
        ### HOW DO YOU TRUST IT? (AT WHAT LEVEL) ###################################
        $LevelToTrustAt = $null
        if ($Levels -and $MultiRuleMode -and (-not $Levels.Count -eq 1)) {
            $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at?" -Levels $Levels
        } elseif (-not $Levels) {
            $LevelToTrustAt = Get-LevelPrompt -Prompt "Which level should this Trust (OR BLOCK) action be applied at??"
        } elseif ($Levels.Count -gt 1) {
            foreach ($Level in $Levels) {
                if (-not $AppTrustLevels.$($Level)) {
                    $LevelToTrustAt = $Level;
                    break;
                } 
            }
        } else {
        #The case that there is only one level
            $LevelToTrustAt = $Levels[0]
            if ($MultiRuleMode) {
                if (-not (Get-YesOrNoPrompt -Prompt "Would you like to set this Trust (OR BLOCK) action at the level of $LevelToTrustAt?")) {
                    return;
                }
            }
        }
        ############################################################################################################


        ### HOW DO YOU TRUST IT? (TRUSTED FOR WHAT POLICY) ##################

        Write-Host "Congrats!" #FIXME

        ############################################################################################################

    } catch {
        throw $_
    }
    
    return $PotentialRuleInfo
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
    When this is provided, only policies linked with a particular group will be considered for linking trust.

    .PARAMETER PolicyName
    When this is provided, rules that are trusted will be automatically applied to the policy with this name! 

    .PARAMETER PolicyGUID
    When this is provided, rules that are trusted will be automatically applied to the policy with this GUID! 

    .PARAMETER PolicyID
    When this is provided, only policies which match this provided PolicyID will be considered for linking trust.

    .PARAMETER OverrideUserorKernelDefaults
    This overrides the default behavior of looking at SigningScenario (for the words "Driver" or "UserMode") when deciding to trust on User Mode or Kernel Mode
    This also overrides the behavior of trusting only on UserMode by default if no SigningScenario is present.
    Instead, the user will be prompted whether to trust the app at the level of kernel mode or user mode.

    .PARAMETER VersioningType
    OPTIONAL: Supply an integer for different versioning behavior for file publishers. These will be written to the database (as publisher index + file name combinations)
    NOTE: VersioningTypes are written to the database when specified with this parameter (or the parameter AlwaysSetMinimumVersions is set)
    NOTE: Options 0-5 deal with the "file_publisher_options" table, options 6-11 deal with the "policy_file_publisher_options" table and options 12-17 write to the "policy_versioning_options" table

        0 - GLOBAL SET MINIMUM - For a particular publisher index + file name combination, prompt the user for a [fixed] MinimumFileVersion that will be applied anytime the combination appears
        1 - GLOBAL DECREMENT MINIMUM - For a particular publisher index + file name combination, replace the MinimumFileVersion with a new one anytime a lower one appears for all appearances of the combination
        2 - GLOBAL ALWAYS SPECIFY - Regardless of which policies have a file publisher rule set, always ask the user for a specific MinimumFileVersion to apply for any instance of the publisher index + file name combination.
        3 - GLOBAL INCREMENT MINIMUM - For a particular publisher index + file name combination, replace the MinimumFileVersion with a new one anytime a GREATER one appears for all appearances of the combination
        4 - GLOBAL 0.0.0.0 MINIMUM - Exactly like option 0, but 0.0.0.0 will always be set to be the MinimumFileVersion without prompting the user
        5 - [MISC OPTION NOT YET IMPLEMENTED]
        6 - EACH POLICY SET MINIMUM - Prompt the user whether they want a [fixed] MinimumFileVersion for each time a new publisher index + file name combination for each individual policy. 
        7 - EACH POLICY DECREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a lower one anytime a lower one is encountered
        8 - EACH POLICY ALWAYS SPECIFY - The exact same as option 2, the only difference being that when the user specifies the desired versioning for one policy, that file name + publisher index combination will be ignored for the rest of the session
        9 - EACH POLICY INCREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a HIGHER one anytime a higher one is encountered
        10 - EACH POLICY 0.0.0.0 Minimum - Exactly like option 6, but the MinimumFileVersion will always be set to 0.0.0.0 without prompting the user
        11 - [MISC OPTION NOT YET IMPLEMENTED]
        12 - Like Option 0 and 6, but the VersioningType will be applied to the entire policy--not dependent on File Name + Publisher Index Combination
        13 - Like Option 1 and 7, but the VersioningType will be applied to the entire policy--not dependent on File Name + Publisher Index Combination
        14 - Like Option 2 and 8, but the VersioningType will be applied to the entire policy--not dependent on File Name + Publisher Index Combination
        15 - Like Option 3 and 9, but the VersioningType will be applied to the entire policy--not dependent on File Name + Publisher Index Combination
        16 - Like Option 4 and 10, but the VersioningType will be applied to the entire policy--not dependent on File Name + Publisher Index Combination
        17 - [MISC OPTION NOT YET IMPLEMENTED]

    .PARAMETER AdvancedVersioning
    Gives more advanced versioning options when conveying trust.
    This runs the cmdlet as if VersioningType was never set and ignores VersioningType values from the database.
    This will also prevent VersioningTypes from being written to the database.

    .PARAMETER IgnoreErrors
    Do not terminate the function based on error count--and ignore the all-or-nothing behavior of updating trust in the database.
    NOTE: There is no all-or-nothing behavior when events are piped into the cmdlet instead of pulled from the database!

    .PARAMETER MSIorScripts
    Pull events with no trust action from the msi_or_script table instead of the apps table.

    .PARAMETER ModifyUniversalVersioning
    Modify the GlobalVersioningType in Resources/LocalStorage.json to reflect that value provided by VersioningType
    NOTE: This VersioningType will be applied to ANY file publisher rule imaginable -- until the value is set back to an empty string "".

    .PARAMETER MultiRuleMode
    Even if an app is already trusted at the specified levels, this option allows you to check to see if you can allow the app at another level--for example, 
    if a file publisher is allowed for one policy and allows an app to run, you can still allow an app by hash for another policy. 
    (This will prompt the user whether they want to allow the other rule.) Can only be set when Level AND fallbacks are specified. 

    .PARAMETER ResetUntrusted
    Reset the untrusted flag for every "untrusted" app in the database (this doesn't reset flags for blocked or revoked)

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
        [Parameter(ValueFromPipeline)]
        [PSCustomObject[]]$Events,
        [switch]$RequireComment,
        [switch]$Purge,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string]$Level,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Fallbacks,
        [string]$GroupName,
        [string]$PolicyName,
        [string]$PolicyGUID,
        [string]$PolicyID,
        [Alias("NoDefault","Override")]
        [switch]$OverrideUserorKernelDefaults,
        [ValidateSet(0,1,2,3,4,6,7,8,9,10,12,13,14,15,16)]
        $VersioningType,
        [switch]$AdvancedVersioning,
        [Alias("Ignore")]
        [switch]$IgnoreErrors,
        [Alias("MSI","Script","MSIorScript")]
        [switch]$MSIorScripts,
        [Alias("UniversalVersioning","UniversalReset")]
        [switch]$ModifyUniversalVersioning,
        [Alias("MultiMode","MultiLevel","MultiLevelMode")]
        [switch]$MultiRuleMode,
        [Alias("Reset")]
        [switch]$ResetUntrusted
    )

    begin {
        if ($Fallbacks -and -not $Level) {
            throw "Cannot provide fallbacks without providing a level. (This would be the preferred or default level.)"
        }

        if ($MultiRuleMode -and -not $Level -and -not $Fallbacks) {
            throw "MultiRuleMode is only allowed when Level and Fallbacks are specified."
        }

        if ($ModifyUniversalVersioning -and -not $VersioningType) {
            throw "When ModifyUniversalVersioning is set, a VersioningType must also be provided."
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
        if ($ModifyUniversalVersioning) {
            try {
                Set-ValueLocalStorageJSON -Key "GlobalVersioningType" -Value $VersioningType -ErrorAction Stop
            } catch {
                Write-Warning "Unable to update cached VersioningType value in LocalStorage.json."
            }
        }

        try {
            $TempVersioningNum = (Get-LocalStorageJSON -ErrorAction Stop)."GlobalVersioningType"
            if ($TempVersioningNum) {
                $VersioningType = $TempVersioningNum
            }
        } catch {
            Write-Warning "Unable to retrieve GlobalVersioningType from LocalStorage.json."
        }

        if (-not $VersioningType -and $AdvancedVersioning) {
            $VersioningType = 2
            if ($TempVersioningNum) {
                Write-Warning "AdvancedVersioning specified. GlobalVersioningType will be ignored."
            }
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
            $Transaction = $Connection.BeginTransaction()

            foreach ($Event in $Events) {

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
                        continue;
                    }

                    if (-not (Find-WDACApp -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop)) {
                    #Even if the app is piped into the cmdlet it still has to exist in the database.
                        continue;
                    }

                    if ((Get-WDACAppUntrustedStatus -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop)) {
                    #Case the user has already set an untrust action on this app
                        continue;
                    }

                    $SigningScenario = $Event.SigningScenario
                    if ($SigningScenario) {
                        if ($AllLevels -and (Get-AppTrusted -SHA256FlatHash $AppHash -Levels $AllLevels -Driver:($SigningScenario -eq "Driver") -UserMode:($SigningScenario -eq "UserMode") -Connection $Connection -ErrorAction Stop)) {
                        #This indicates that the app is already trusted at a higher level
                            if ($MultiRuleMode -and $AllLevels.Count -ge 1) {
                                $MiscLevels = @()
                                $AppTrustAllLevels = (Get-AppTrustedAllLevels -SHA256FlatHash $AppHash -Connection $Connection -ErrorAction Stop).PSObject.Properties | Where-Object {-not $_.Value} | Select-Object Name
                                foreach ($AppTrustLevel in $AppTrustAllLevels) {
                                #This checks for if there are any remaining untrusted levels for which to use MultiRuleMode
                                    $MiscLevels += $AppTrustLevel.Name
                                }
                                if ($MiscLevels.Count -ge 1) {
                                    Write-Verbose "Multi-Rule Mode Initiated for this app: $FileName.";
                                    Read-WDACConferredTrust -SHA256FlatHash $AppHash -RequireComment:$RequireComment -Levels $MiscLevels -GroupName $GroupName -PolicyName $PolicyName -PolicyGUID $PolicyGUID -PolicyID $PolicyID -OverrideUserorKernelDefaults:$OverrideUserorKernelDefaults -VersioningType $VersioningType -AdvancedVersioning:$AdvancedVersioning -MultiRuleMode -Connection $Connection -ErrorAction Stop
                                    continue;
                                }
                            }
                            Write-Verbose "Higher level of trust already achieved for this app: $FileName with hash $AppHash"
                            continue;
                        }
                    }

                    Read-WDACConferredTrust -SHA256FlatHash $AppHash -RequireComment:$RequireComment -Levels $AllLevels -GroupName $GroupName -PolicyName $PolicyName -PolicyGUID $PolicyGUID -PolicyID $PolicyID -OverrideUserorKernelDefaults:$OverrideUserorKernelDefaults -VersioningType $VersioningType -AdvancedVersioning:$AdvancedVersioning -Connection $Connection -ErrorAction Stop

                } catch {
                    Write-Warning "Could not apply trust action to the database for this app: $($AppHash)."
                    Write-Verbose $_
                    $ErrorCount += 1
                    continue
                }
            }
        } catch {
            throw $_
        }

        $Transaction.Commit()
        $Connection.Close()
        Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue

        Write-Host "Successfully updated trust for those potential rules in the database. Use Merge-TrustedWDACRules to merge them into policies."
    }

    end {
        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }
    }
}