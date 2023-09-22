function CommentPreserving {
    [CmdletBinding()]
    param (
        $IDsAndComments,
        $FilePath
    )

    $FileContent = Get-Content $FilePath -ErrorAction Stop
    $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-F0-9]+(?=")'
    $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-F0-9]+(?=")'
    $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-F0-9]+(?=")'
    $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-F0-9]+(?=")'
    $CommentPattern = "(?<=<!--).+(?=-->)"

    for ($i=0; $i -lt $FileContent.Count; $i++) {
        if ( (($FileContent[$i] -match $Pattern1) -or ($FileContent[$i] -match $Pattern2) -or ($FileContent[$i] -match $Pattern3) -or ($FileContent[$i] -match $Pattern4)) -and ($i -gt 0)) {
            $TempID = $Matches[0]
            if ($IDsAndComments[$TempID] -eq $true -and ($FileContent[$i -1] -match $CommentPattern)) {
                $IDsAndComments[$TempID] = $Matches[0]
            }
        }
    }

    return $IDsAndComments
}

function Add-LineBeforeSpecificLine {
    [CmdletBinding()]
    param (
        $Line,
        $LineNumber,
        $FilePath
    )

    if ($LineNumber -le 1) {
        throw "Cannot append line at this location."
    }

    $FileContent = Get-Content -Path $FilePath
    $result = @()
    for ($i=0; $i -lt $FileContent.Count; $i++) {
        $result += $FileContent[$i]
        if ($i -eq ($LineNumber - 2)) {
        #The reason we subtract 2 here instead of 1 is because the count starts at 0 while the line numbers start at 1
            $result += $Line
        }
    }

    $result | Set-Content -Path $FilePath -Force
}

function Add-WDACRuleComments {
    [CmdletBinding()]
    param (
        $IDsAndComments,
        $FilePath
    )

    foreach ($Entry in $IDsAndComments.GetEnumerator()) {
        if (($Entry.Value) -and ($Entry.Value -ne $true)) {
            $ID = $Entry.Key
            $Comment = ("<!--" + $Entry.Value + "-->")
            $IDInstances = Select-String -Path $FilePath -Pattern $ID

            for ($i=0; $i -lt $IDInstances.Count; $i++) {
                #The reason we grab a second time for each instance is that line numbers are all changed once a line is appended to a location
                $IDInstances2 = Select-String -Path $FilePath -Pattern $ID

                foreach ($IDInstance in $IDInstances2) {
                    if (($IDInstances[$i]).Line -eq $IDInstance.Line) {
                        if ( ($IDInstance.LineNumber) -gt 1) {
                            if (-not (((Get-Content $FilePath -TotalCount ($IDInstance.LineNumber -1))[-1] -match "<!--") -or ((Get-Content $FilePath -TotalCount ($IDInstance.LineNumber -1))[-1] -match "-->"))) {
                            #If there is not already a comment above the line where the ID appears
                            
                                Add-LineBeforeSpecificLine -Line $Comment -LineNumber $IDInstance.LineNumber -FilePath $FilePath -ErrorAction Stop
                                break;
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }
}

function Update-NewIDs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $IDsAndComments,
        $PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $CurrentPolicyRules = Get-CIPolicy -FilePath (Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -ErrorAction Stop
    foreach ($currentRule in $CurrentPolicyRules) {
        if (-not ($IDsAndComments[$currentRule.Id])) {
        #The only reason this check is necessary, is rules with a certain ID are duplicated based on if they are used for UserMode or Kernel mode
        #...Which then causes an error if you try to add that ID a second time
            $IDsAndComments.Add($currentRule.Id,$true)
        }
    }

    return $IDsAndComments
}

function Edit-WDACPolicy {
    <#
    .SYNOPSIS
    Edit a WDAC policy by adding or removing some options (a policy entry in the database is required)
    
    .DESCRIPTION
    TODO

    Author: Nathan Jepson
    License: MIT License

    .EXAMPLE
    TODO

    .EXAMPLE
    TODO
    
    #>
    [CmdletBinding()]
    Param (
        [Alias("RetainCopy","KeepOld","RetainOld")]
        [switch]$NoOverwrite,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [switch]$AddPSCodeSigner,
        [switch]$UpdatePolicySigner,
        [switch]$SupplementalPolicySigner,
        [Alias("NoCache")]
        [switch]$DoNotCacheRecommended,
        [Alias("AddDriverBlockRules")]
        [switch]$DriverBlockRules,
        [Alias("UserModeBlockRules","AddUserModeBlockRules","AddOtherBlockRules")]
        [switch]$OtherBlockRules,
        [Alias("Windows","AddWindows","AddWindowsMode","WindowsMode")]
        [switch]$DefaultWindowsMode,
        [Alias("Microsoft","AddMicrosoftMode","MicrosoftMode")]
        [switch]$AllowMicrosoftMode,
        [Alias("RemoveUnsigned","AddSigned")]
        [switch]$Signed,
        [Alias("AddUnsigned","RemoveSigned")]
        [switch]$Unsigned,
        [Alias("RemoveEnforce","RemoveEnforced","AddAudit")]
        [switch]$Audit,
        [Alias("AddEnforced","AddEnforce","Enforce")]
        [switch]$RemoveAudit,
        [Alias("UserModeCodeIntegrity","AddUMCI")]
        [switch]$UMCI,
        [switch]$RemoveUMCI,
        [Alias("AddBootMenuProtection")]
        [switch]$BootMenuProtection,
        [Alias("DisableBootMenuProtection")]
        [switch]$RemoveBootMenuProtection,
        [Alias("AddWHQL")]
        [switch]$WHQL,
        [Alias("DisableWHQL")]
        [switch]$RemoveWHQL,
        [Alias("AddDisableFlightSigning")]
        [switch]$DisableFlightSigning,
        [Alias("EnableFlightSigning")]
        [switch]$RemoveDisableFlightSigning,
        [Alias("AddInheritDefaultPolicy")]
        [switch]$InheritDefaultPolicy,
        [switch]$RemoveInheritDefaultPolicy,
        [Alias("AddAllowDebugPolicyAugmented")]
        [switch]$AllowDebugPolicyAugmented,
        [switch]$RemoveAllowDebugPolicyAugmented,
        [Alias("AddRequireEVSigners")]
        [switch]$RequireEVSigners,
        [switch]$RemoveRequireEVSigners,
        [Alias("AddAdvancedBootOptionsMenu")]
        [switch]$AdvancedBootOptionsMenu,
        [Alias("DisableAdvancedBootOptionsMenu")]
        [switch]$RemoveAdvancedBootOptionsMenu,
        [Alias("AddBootAuditOnFailure")]
        [switch]$BootAuditOnFailure,
        [switch]$RemoveBootAuditOnFailure,
        [Alias("AddDisableScriptEnforcement")]
        [switch]$DisableScriptEnforcement,
        [Alias("EnableScriptEnforcement")]
        [switch]$RemoveDisableScriptEnforcement,
        [Alias("Store","AddEnforceStoreApps","AddStore")]
        [switch]$EnforceStoreApps,
        [Alias("UnenforceStoreApps")]
        [switch]$RemoveEnforceStoreApps,
        [Alias("AddEnableManagedInstaller")]
        [switch]$EnableManagedInstaller,
        [Alias("RemoveManagedInstaller","DisableManagedInstaller")]
        [switch]$RemoveEnableManagedInstaller,
        [Alias("IntelligentSecurityGraph","AddISG","AddIntelligentSecurityGraph")]
        [switch]$ISG,
        [switch]$RemoveISG,
        [Alias("AddInvalidateEAsOnReboot")]
        [switch]$InvalidateEAsOnReboot,
        [switch]$RemoveInvalidateEAsOnReboot,
        [Alias("AddUpdatePolicyNoReboot")]
        [switch]$UpdatePolicyNoReboot,
        [switch]$RemoveUpdatePolicyNoReboot,
        [Alias("AddAllowSupplementalPolicies")]
        [switch]$AllowSupplementalPolicies,
        [Alias("DisableSupplementalPolicies","DenySupplementalPolicies")]
        [switch]$RemoveAllowSupplementalPolicies,
        [Alias("AddDisableRuntimeFilepathRules")]
        [switch]$DisableRuntimeFilepathRules,
        [Alias("EnableRuntimeFilepathRules")]
        [switch]$RemoveDisableRuntimeFilepathRules,
        [Alias("AddDynamicCodeSecurity")]
        [switch]$DynamicCodeSecurity,
        [switch]$RemoveDynamicCodeSecurity,
        [Alias("AddTreatRevokedAsUnsigned")]
        [switch]$TreatRevokedAsUnsigned,
        [switch]$RemoveTreatRevokedAsUnsigned,
        [Alias("AddHVCI")]
        [switch]$HVCI,
        [Alias("DisableHVCI")]
        [switch]$RemoveHVCI,
        [Alias("AddStrictHVCI")]
        [switch]$StrictHVCI
    )
    
    if ($AllowDebugPolicyAugmented -or $RequireEVSigners -or $RemoveAllowDebugPolicyAugmented -or $RemoveRequireEVSigners) {
        throw "`"Debug Policy Augmented`" or `"Require EV Signers`" is not yet supported by Microsoft."
    }

    if ($Signed -and $Unsigned) {
        throw "Cannot set as Signed and Unsigned"
    }

    if ($Audit -and $RemoveAudit) {
        throw "Cannot set both Audit and RemoveAudit (Enforce)"
    }

    if ($PolicyGUID -and $PolicyName) {
        throw "Please provide either a PolicyGUID or PolicyName, but not both"
    }

    if (-not ($PolicyGUID -or $PolicyName)) {
        throw "Please provide either a PolicyGUID or PolicyName to designate the policy to edit."
    }

    if (($UMCI -and $RemoveUMCI) -or ($BootMenuProtection -and $RemoveBootMenuProtection) -or ($WHQL -and $RemoveWHQL) -or ($DisableFlightSigning -and $RemoveDisableFlightSigning) `
    -or ($InheritDefaultPolicy -and $RemoveInheritDefaultPolicy) -or ($AdvancedBootOptionsMenu -and $RemoveAdvancedBootOptionsMenu) -or ($BootAuditOnFailure -and $RemoveBootAuditOnFailure) `
    -or ($DisableScriptEnforcement -and $RemoveDisableScriptEnforcement) -or ($EnforceStoreApps -and $RemoveEnforceStoreApps) -or ($EnableManagedInstaller -and $RemoveEnableManagedInstaller) `
    -or ($ISG -and $RemoveISG) -or ($InvalidateEAsOnReboot -and $RemoveInvalidateEAsOnReboot) -or ($UpdatePolicyNoReboot -and $RemoveUpdatePolicyNoReboot) `
    -or ($AllowSupplementalPolicies -and $RemoveAllowSupplementalPolicies) -or ($DisableRuntimeFilepathRules -and $RemoveDisableRuntimeFilepathRules) -or ($DynamicCodeSecurity -and $RemoveDynamicCodeSecurity) `
    -or ($TreatRevokedAsUnsigned -and $RemoveTreatRevokedAsUnsigned) -or ($HVCI -and $RemoveHVCI) -or ($HVCI -and $StrictHVCI) -or ($StrictHVCI -and $RemoveHVCI)) {
        throw "Contradictory flags detected."
    }

    if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
        Write-Verbose "The current file is in the SignedModules folder."
    } else {
        $PSModuleRoot = $PSScriptRoot
    }


    try {
        $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
        $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"

        if (-not $WorkingPoliciesLocation -or -not $WorkingPoliciesLocationType -or "" -eq $WorkingPoliciesLocation -or "" -eq $WorkingPoliciesLocationType) {
            throw "Null or invalid values provided for Working Policies location (or the location type)"
        }
    } catch {
        Write-Verbose $_
        throw "Trouble in retrieving your working policies location."
    }

    if ($Signed) {
        try {
            $WDACodeSigner = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
            if (-not $WDACodeSigner -or "" -eq $WDACodeSigner) {
                throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
            } elseif (-not ($WDACodeSigner.ToLower() -match "cert\:\\")) {
                throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            }
        } catch {
           throw $_
        }
    }

    if ($AddPSCodeSigner) {
        try {
            $PSCodeSigner = (Get-LocalStorageJSON -ErrorAction Stop)."PowerShellCodeSigningCertificate"
            if (-not $PSCodeSigner -or "" -eq $PSCodeSigner) {
                throw "Error: Empty or null value for PowerShell code signing certificate retreived from Local Storage."
            } elseif (-not ($PSCodeSigner.ToLower() -match "cert\:\\")) {
                throw "Local cache does not specify a valid certificate path for the PowerShell code signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            }
        } catch {
            throw $_
        }
    }

    try {

        if ($PolicyGUID) {
            if (-not (Find-WDACPolicy -PolicyGUID $PolicyGUID -ErrorAction Stop)) {
                throw "No policy with GUID $PolicyGUID  exists in the database."
            }
        } elseif ($PolicyName) {
            if (-not (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop)) {
                throw "No policy with name $PolicyName exists."
            }
            $PolicyGUID = (Get-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop).PolicyGUID
        }
        
    } catch {
        Write-Verbose $_
        throw "Failed to import Sqlite OR a problem with connecting to the trust database."
    }

    $BackupPolicyLocation = $null
    $OldPolicyPath = (Get-FullPolicyPath -PolicyGUID $PolicyGUID -ErrorAction Stop)
    $TempPolicyPath = $null

    try {
        $RandomGUID = New-Guid
        $RandomGUID2 = New-Guid
        $TempPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$($PolicyName)_$RandomGUID.xml")
        $BackupPolicyLocation = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$($PolicyName)_$RandomGUID2.xml")
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        $IDsAndComments = @{}
        $CurrentPolicyRules = Get-CIPolicy -FilePath (Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -ErrorAction Stop
        foreach ($currentRule in $CurrentPolicyRules) {
            if (-not ($IDsAndComments[$currentRule.Id])) {
            #The only reason this check is necessary, is rules with a certain ID are duplicated based on if they are used for UserMode or Kernel mode
            #...Which then causes an error if you try to add that ID a second time
                $IDsAndComments.Add($currentRule.Id,$true)
            }
        }
        $FullCurrentPolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $FullCurrentPolicyPath -ErrorAction Stop
        
        Copy-Item $FullCurrentPolicyPath -Destination $TempPolicyPath -Force -ErrorAction Stop
        Copy-Item $FullCurrentPolicyPath -Destination $BackupPolicyLocation -Force -ErrorAction Stop

            if ($DriverBlockRules) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                $DriverBlockRulesTask = PowerShell {
                    [CmdletBinding()]
                    Param(
                        $TempPolicyPath,
                        $PSModuleRoot,
                        $DoNotCacheRecommended,
                        $IsVerbose,
                        $IDsAndComments
                    )

                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1") -ErrorAction Stop;
                        $driverrules = Get-DriverBlockRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                        $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]*(?=")'
                        for ($i=0; $i -lt $driverrules.Count; $i++) {
                            if ($IDsAndComments[$($driverrules[$i].Id)]) {
                                if ($driverrules[$i].Id -match $Pattern1) {
                                    $NewID = IncrementAllowID -RuleMap $IDsAndComments
                                } elseif ($driverrules[$i].Id -match $Pattern2) {
                                    $NewID = IncrementDenyID -RuleMap $IDsAndComments
                                }
                                elseif ($driverrules[$i].Id -match $Pattern3) {
                                    $NewID = IncrementSignerID -RuleMap $IDsAndComments
                                }
                                elseif ($driverrules[$i].Id -match $Pattern4) {
                                    $NewID = IncrementFileAttribID -RuleMap $IDsAndComments
                                }
                                $driverrules[$i].Id = $NewID
                                $IDsAndComments = $IDsAndComments + @{$NewID=$true}
                            }
                        }
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $driverrules -ErrorAction Stop | Out-Null;
                        Remove-UnderscoreDigits -FilePath $TempPolicyPath
                    } catch {
                        Write-Error $_
                        return $false
                    }
                    
                    return $true

                } -args $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference,$IDsAndComments

                if (-not $DriverBlockRulesTask) {
                    throw "Unable to merge with driver block rules. Error occurred."
                }

                if ($IDsAndComments) {
                #The function below doesn't accept the IDsAndComments input if any entries are null
                    $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
                }
            }

            if ($OtherBlockRules) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                $UserModeBlockRulesTask = PowerShell {
                    [CmdletBinding()]
                    Param(
                        $TempPolicyPath,
                        $PSModuleRoot,
                        $DoNotCacheRecommended,
                        $IsVerbose,
                        $IDsAndComments
                    )
                    
                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1") -ErrorAction Stop;
                        $usermoderules = Get-UserModeBlockRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                        $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]*(?=")'
                        for ($i=0; $i -lt $usermoderules.Count; $i++) {
                            if ($IDsAndComments[$($usermoderules[$i].Id)]) {
                                if ($usermoderules[$i].Id -match $Pattern1) {
                                    $NewID = IncrementAllowID -RuleMap $IDsAndComments
                                } elseif ($usermoderules[$i].Id -match $Pattern2) {
                                    $NewID = IncrementDenyID -RuleMap $IDsAndComments
                                }
                                elseif ($usermoderules[$i].Id -match $Pattern3) {
                                    $NewID = IncrementSignerID -RuleMap $IDsAndComments
                                }
                                elseif ($usermoderules[$i].Id -match $Pattern4) {
                                    $NewID = IncrementFileAttribID -RuleMap $IDsAndComments
                                }
                                $usermoderules[$i].Id = $NewID
                                $IDsAndComments = $IDsAndComments + @{$NewID=$true}
                            }
                        }
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $usermoderules -ErrorAction Stop | Out-Null;
                        Remove-UnderscoreDigits -FilePath $TempPolicyPath
                    } catch {
                        Write-Error $_
                        return $false
                    }
                    
                    return $true

                } -args $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference,$IDsAndComments

                if (-not $UserModeBlockRulesTask) {
                    throw "Unable to merge with user mode block rules. Error occurred."
                }

                if ($IDsAndComments) {
                    $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
                }
            }



            if ($DefaultWindowsMode) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(

                $WindowsModeTask = PowerShell {
                    [CmdletBinding()]
                    Param(
                        $TempPolicyPath,
                        $PSModuleRoot,
                        $DoNotCacheRecommended,
                        $IsVerbose,
                        $IDsAndComments
                    )
                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1") -ErrorAction Stop;
                        $rules = Get-WindowsModeRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                        $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]*(?=")'
                        for ($i=0; $i -lt $rules.Count; $i++) {
                            if ($IDsAndComments[$($rules[$i].Id)]) {
                                if ($rules[$i].Id -match $Pattern1) {
                                    $NewID = IncrementAllowID -RuleMap $IDsAndComments
                                } elseif ($rules[$i].Id -match $Pattern2) {
                                    $NewID = IncrementDenyID -RuleMap $IDsAndComments
                                }
                                elseif ($rules[$i].Id -match $Pattern3) {
                                    $NewID = IncrementSignerID -RuleMap $IDsAndComments
                                }
                                elseif ($rules[$i].Id -match $Pattern4) {
                                    $NewID = IncrementFileAttribID -RuleMap $IDsAndComments
                                }
                                $rules[$i].Id = $NewID
                                $IDsAndComments = $IDsAndComments + @{$NewID=$true}
                            }
                        }
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $rules -ErrorAction Stop | Out-Null;
                        Remove-UnderscoreDigits -FilePath $TempPolicyPath
                    } catch {
                        Write-Error $_
                        return $false
                    }

                    return $true

                } -args $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference,$IDsAndComments
                if (-not $WindowsModeTask) {
                    throw "Unable to merge with Default Windows Mode rules. Error occurred."
                }

                if ($IDsAndComments) {
                    $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
                }
            }

            if ($AllowMicrosoftMode) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(

                $AddMicrosoftModeTask = PowerShell {
                    [CmdletBinding()]
                    Param(
                        $TempPolicyPath,
                        $PSModuleRoot,
                        $DoNotCacheRecommended,
                        $IsVerbose,
                        $IDsAndComments
                    )

                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1") -ErrorAction Stop;
                        $rules = Get-AllowMicrosoftModeRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                        $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]*(?=")'
                        $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]*(?=")'
                        for ($i=0; $i -lt $rules.Count; $i++) {
                            if ($IDsAndComments[$($rules[$i].Id)]) {
                                if ($rules[$i].Id -match $Pattern1) {
                                    $NewID = IncrementAllowID -RuleMap $IDsAndComments
                                } elseif ($rules[$i].Id -match $Pattern2) {
                                    $NewID = IncrementDenyID -RuleMap $IDsAndComments
                                }
                                elseif ($rules[$i].Id -match $Pattern3) {
                                    $NewID = IncrementSignerID -RuleMap $IDsAndComments
                                }
                                elseif ($rules[$i].Id -match $Pattern4) {
                                    $NewID = IncrementFileAttribID -RuleMap $IDsAndComments
                                }
                                $rules[$i].Id = $NewID
                                $IDsAndComments = $IDsAndComments + @{$NewID=$true}
                            }
                        }
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $rules -ErrorAction Stop | Out-Null;
                        Remove-UnderscoreDigits -FilePath $TempPolicyPath
                    } catch {
                        Write-Error $_
                        return $false
                    }

                    return $true
                    
                } -args $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference,$IDsAndComments

                if (-not $AddMicrosoftModeTask) {
                    throw "Unable to merge with Microsoft Mode rules. Error occurred."
                }

                if ($IDsAndComments) {
                    $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
                }
            }

            #Add Code Signing / Policy Signing Rules: =====================================================================
            if ($AddPSCodeSigner) {
                Export-CodeSignerAsCER -Destination (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -PSCodeSigner -ErrorAction Stop | Out-Null
                Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -User -Kernel -ErrorAction Stop
                $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            }

            if ($UpdatePolicySigner -or $SupplementalPolicySigner) {
                Export-CodeSignerAsCER -Destination (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -WDACCodeSigner -ErrorAction Stop | Out-Null
                if ($UpdatePolicySigner) {
                    Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Update -ErrorAction Stop
                } 
                if ($SupplementalPolicySigner) {
                    Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Supplemental -ErrorAction Stop
                }
                $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            }

        #Apply Policy Options ======================================================
        #This is slightly different from "New-WDACPolicy" in that if a flag isn't set, a rule is not specified, it is not removed or added 
        #...(hence the "elseifs" instead of just "else")
    
            #Case 0: 'Enabled:UMCI'
            if ($UMCI) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 0
            } elseif ($RemoveUMCI) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 0 -Delete
            }

            #Case 1: 'Enabled:Boot Menu Protection'
            if ($BootMenuProtection) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 1
            } elseif ($RemoveBootMenuProtection) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 1 -Delete
            }

            #Case 2: 'Required:WHQL'
            if ($WHQL) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 2
            } elseif ($RemoveWHQL) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 2 -Delete
            }

            #Case 3: 'Enabled:Audit Mode'
            if ($Audit) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 3
            } elseif ($RemoveAudit) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 3 -Delete
            }

            #Case 4: 'Disabled:Flight Signing'
            if ($DisableFlightSigning) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 4
            } elseif ($RemoveDisableFlightSigning) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 4 -Delete
            }

            #Case 5: 'Enabled:Inherit Default Policy'
            if ($InheritDefaultPolicy) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 5
            } elseif ($RemoveInheritDefaultPolicy) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 5 -Delete
            }

            #Case 6: 'Enabled:Unsigned System Integrity Policy'
            if ($Unsigned) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 6
            } elseif ($Signed) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 6 -Delete
            }
            
            #Case 7: 'Allowed:Debug Policy Augmented'
            #Not yet supported by Microsoft

            #Case 8: 'Required:EV Signers'
            #Not yet supported by Microsoft

            #Case 9: 'Enabled:Advanced Boot Options Menu'
            if ($AdvancedBootOptionsMenu) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 9
            } elseif ($RemoveAdvancedBootOptionsMenu) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 9 -Delete
            }

            #Case 10: 'Enabled:Boot Audit On Failure'
            if ($BootAuditOnFailure) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 10
            } elseif ($RemoveBootAuditOnFailure) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 10 -Delete
            }

            #Case 11: 'Disabled:Script Enforcement'
            if ($DisableScriptEnforcement) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 11
            } elseif ($RemoveDisableScriptEnforcement) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 11 -Delete
            }

            #Case 12: 'Required:Enforce Store Applications'
            if ($EnforceStoreApps) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 12
            } elseif ($RemoveEnforceStoreApps) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 12 -Delete
            }

            #Case 13: 'Enabled:Managed Installer'
            if ($EnableManagedInstaller) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 13
            } elseif ($RemoveEnableManagedInstaller) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 13 -Delete
            }

            #Case 14:'Enabled:Intelligent Security Graph Authorization'
            if ($ISG) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 14
            } elseif ($RemoveISG) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 14 -Delete
            }

            #Case 15:'Enabled:Invalidate EAs on Reboot'
            if ($InvalidateEAsOnReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 15
            } elseif ($RemoveInvalidateEAsOnReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 15 -Delete
            }

            #Case 16:'Enabled:Update Policy No Reboot'
            if ($UpdatePolicyNoReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 16
            } elseif ($RemoveUpdatePolicyNoReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 16 -Delete
            }

            #Case 17:'Enabled:Allow Supplemental Policies'
            if ($AllowSupplementalPolicies) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 17
            } elseif ($RemoveAllowSupplementalPolicies) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 17 -Delete
            }

            #Case 18:'Disabled:Runtime FilePath Rule Protection'
            if ($DisableRuntimeFilepathRules) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 18
            } elseif ($RemoveDisableFlightSigning) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 18 -Delete
            }

            #Case 19:'Enabled:Dynamic Code Security'
            if ($DynamicCodeSecurity) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 19
            } elseif ($RemoveDynamicCodeSecurity) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 19 -Delete
            }

            #Case 20:'Enabled:Revoked Expired As Unsigned'
            if ($TreatRevokedAsUnsigned) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 20
            } elseif ($RemoveTreatRevokedAsUnsigned) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 20 -Delete
            }

            #Case HVCI: Whether HVCI is enabled
            if ($HVCI) {
                Set-HVCIOptions -Enabled -FilePath $TempPolicyPath
            } elseif ($RemoveHVCI) {
                Set-HVCIOptions -None -FilePath $TempPolicyPath
            } elseif ($StrictHVCI) {
                Set-HVCIOptions -Strict -FilePath $TempPolicyPath
            }
            #===========================================================================

            Add-WDACRuleComments -IDsAndComments $IDsAndComments -FilePath $TempPolicyPath -ErrorAction Stop
            if ($NoOverwrite) {
                #Despite the name, this is not backed up to the $BackupPolicyLocation, this is backed up to the WorkingPolicies directory
                Backup-CurrentPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            }
            Receive-FileAsPolicy -FilePath $TempPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            $PolicyVersion = (Get-PolicyVersionNumber -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion
            if ($PolicyVersion) {
                New-WDACPolicyVersionIncrementOne -PolicyGUID $PolicyGUID -CurrentVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
                $Transaction.Commit()
                Write-Host "Successfully committed changes to Policy $PolicyGUID" -ForegroundColor Green
                if ($PSModuleRoot) {
                    if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer")) {
                        Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -Force
                    }
            
                    if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer")) {
                        Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Force
                    }
                }
                if ($TempPolicyPath) {
                    if (Test-Path $TempPolicyPath) {
                        Remove-Item $TempPolicyPath -Force
                    }
                }
                $Connection.Close()
            } else {
                $Transaction.Rollback()
                $Connection.Close()
                throw "Unable to retrieve version information regarding a policy from the database."
            }

    } catch {
        $theError = $_

        if ($TempPolicyPath) {
            if (Test-Path $TempPolicyPath) {
                Remove-Item $TempPolicyPath -Force
            }
        }

        if ($Transaction) {
            $Transaction.Rollback()
        }

        if ($Connection) {
            $Connection.Close()
        }

        if ($PSModuleRoot) {
            if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer")) {
                Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -Force
            }
    
            if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer")) {
                Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Force
            }
        }

        if ($BackupPolicyLocation -and $OldPolicyPath) {
            try {
                Copy-Item $BackupPolicyLocation -Destination $OldPolicyPath -Force -ErrorAction Stop
                Remove-Item $BackupPolicyLocation -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Could not restore policy file to original location, but it can be recovered at $BackupPolicyLocation"
            }
        }

        Write-Verbose ($_ | Format-List * -Force | Out-String)
        throw $theError
    }
}