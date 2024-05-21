$ThisIsASignedModule = $false
if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\JSON-LocalStorageTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Code-Signing-Tools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Code-Signing-Tools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\Code-Signing-Tools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part2.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part2.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools_Part2.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\WorkingPolicies-and-DB-IO.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1")
}

function CommentPreserving {
    [CmdletBinding()]
    param (
        $IDsAndComments,
        $FilePath
    )

    $FileContent = Get-Content $FilePath -ErrorAction Stop
    $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]+(?=")'
    $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]+(?=")'
    $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]+(?=")'
    $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]+(?=")'
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
            $ID = "`"" + $Entry.Key + "`""
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

function New-CommentMap {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $FilePath
    )

    $IDsAndComments = @{}
    
    $CurrentPolicyRules = Get-CIPolicy -FilePath $FilePath -ErrorAction Stop
    foreach ($currentRule in $CurrentPolicyRules) {
        if (-not ($IDsAndComments[$currentRule.Id])) {
        #The only reason this check is necessary, is rules with a certain ID are duplicated based on if they are used for UserMode or Kernel mode
        #...Which then causes an error if you try to add that ID a second time
            $IDsAndComments.Add($currentRule.Id,$true)
        }
    }

    return $IDsAndComments
}

function Update-NewIDs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $IDsAndComments,
        $PolicyGUID,
        $PolicyPath,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if ($PolicyGUID -and $PolicyPath) {
        throw "Cannot provide both PolicyGUID and PolicyPath to function Update-NewIDs"
    }

    if ($PolicyPath) {
        $CurrentPolicyRules = Get-CIPolicy -FilePath $PolicyPath -ErrorAction Stop
    } elseif ($PolicyGUID) {
        $CurrentPolicyRules = Get-CIPolicy -FilePath (Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -ErrorAction Stop
    } else {
        throw "Please provide a policy GUID or a policy path"
    }

    foreach ($currentRule in $CurrentPolicyRules) {
        if (-not ($IDsAndComments[$currentRule.Id])) {
        #The only reason this check is necessary, is rules with a certain ID are duplicated based on if they are used for UserMode or Kernel mode
        #...Which then causes an error if you try to add that ID a second time
            $IDsAndComments.Add($currentRule.Id,$true)
        }
    }

    return $IDsAndComments
}

function Update-CommentsMapWithUnderscores {
    [CmdletBinding()]
    param (
        $IDsAndComments
    )

    $AllKeys = $IDsAndComments

    foreach ($Item in $AllKeys.GetEnumerator()) {
        $CurrentID = $Item.Key

        $IDsAndComments = $IDsAndComments + @{"$($CurrentID)_0" = $Item.Value}
        $IDsAndComments.Remove($CurrentID)
    }

    return $IDsAndComments
}

function Edit-WDACPolicy {
    <#
    .SYNOPSIS
    Edit a WDAC policy by adding or removing some options (a policy entry in the database is required)
    
    .DESCRIPTION
    You can set or unset many of the options described by Microsoft: 
    (https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create)
    You can add a WDACPolicy signer and Powershell code signer (much like New-WDACPolicy)
    You can set HVCI options, including strict with -StrictHVCI (corresponds to option "2" of Set-HVCIOptions ).
    You can even merge with Microsoft's recommended driver or usermode block rules. (Again, just like New-WDACPolicy.) Or merge with Windows Mode / ALlow Microsoft policies (also created by Microsoft.)
    NOTE: This cmdlet cannot detect whether driver or usermode block rules or windows / microsoft modes are already merged into a policy!
    There is a provision to backup the old version of the policy (NoOverwrite)

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER NoOverwrite
    Retain a backup of the current policy before applying changes.

    .PARAMETER DoNotCacheRecommended
    Cache of the Microsoft recommended policies will not be cached (will be pulled right from GitHub on the next run)

    .PARAMETER Pillar
    Setting the pillar attribute on a policy will make sure that the policy will be applied to every device in the database.

    .EXAMPLE
    Edit-WDACPolicy -PolicyGUID "fd04c607-e1d9-4416-954a-b6f3817c9d10" -StrictHVCI -AddPSCodeSigner -DriverBlockRules -DefaultWindowsMode -NoOverwrite -Verbose 

    .EXAMPLE
    Edit-WDACPolicy -PolicyGUID "fd04c607-e1d9-4416-954a-b6f3817c9d10" -UpdatePolicySigner -SupplementalPolicySigner -RemoveWHQL -RemoveISG -EnableScriptEnforcement

    .EXAMPLE
    Edit-WDACPolicy -PolicyName "CashiersPolicy"
        Note: If you use Edit-WDACPolicy without setting any of the flags, then the version number should just increment by one.
    
    #>
    [CmdletBinding()]
    Param (
        [switch]$Pillar,
        [switch]$RemovePillar,
        [Alias("RetainCopy","KeepOld","RetainOld")]
        [switch]$NoOverwrite,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Alias("PSCodeSigner")]
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

    if ($ThisIsASignedModule) {
        Write-Verbose "The current file is in the SignedModules folder."
    }
    
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
                throw "No policy with GUID $PolicyGUID exists in the database."
            }
        } elseif ($PolicyName) {
            if (-not (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop)) {
                throw "No policy with name $PolicyName exists."
            }
            $PolicyGUID = (Get-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop).PolicyGUID
        }
        
    } catch {
        Write-Verbose $_
        throw "Failed to find policy OR import Sqlite OR a problem with connecting to the trust database."
    }

    $BackupPolicyLocation = $null
    $OldPolicyPath = (Get-FullPolicyPath -PolicyGUID $PolicyGUID -ErrorAction Stop)
    $TempPolicyPath = $null
    $HVCIOption = $null
    $Connection = $null
    $Transaction = $null

    try {
        $RandomGUID = New-Guid
        $RandomGUID2 = New-Guid
        $TempPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$($PolicyName)_$RandomGUID.xml")
        $BackupPolicyLocation = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$($PolicyName)_$RandomGUID2.xml")
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        $HVCIOption = Get-HVCIPolicySetting -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $IsSupplemental = Get-WDACPolicySupplementalStatus -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        if ($IsSupplemental -and $SupplementalPolicySigner) {
            throw "Cannot add a supplemental policy signer to a supplemental policy; it must be added to the base policy."
        }
        $IDsAndComments = New-CommentMap -FilePath (Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -ErrorAction Stop        
        $FullCurrentPolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $FullCurrentPolicyPath -ErrorAction Stop
        
        Copy-Item $FullCurrentPolicyPath -Destination $TempPolicyPath -Force -ErrorAction Stop
        Copy-Item $FullCurrentPolicyPath -Destination $BackupPolicyLocation -Force -ErrorAction Stop

            if ($DriverBlockRules) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                $DriverBlockRulesTask = {

                    $InputArray = @($input)
                    $TempPolicyPath = $InputArray[0]
                    $PSModuleRoot = $InputArray[1]
                    $DoNotCacheRecommended = $InputArray[2]
                    $IsVerbose = $InputArray[3]

                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        $driverrules = Get-DriverBlockRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                       
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $driverrules -ErrorAction Stop | Out-Null;
                    } catch {
                        Write-Error $_
                        return $false
                    }
                    
                    return $true
                }

                $DriverBlockRulesTaskResult = $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference | PowerShell $DriverBlockRulesTask 

                if (-not $DriverBlockRulesTaskResult) {
                    throw "Unable to merge with driver block rules. Error occurred."
                }

                $AppendedZeroes = Update-CommentsMapWithUnderscores -IDsAndComments $IDsAndComments -ErrorAction Stop
                Add-WDACRuleComments -IDsAndComments $AppendedZeroes -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = New-CommentMap -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $TempPolicyPath -ErrorAction Stop
            }

            if ($OtherBlockRules) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                $UserModeBlockRulesTask = {

                    $InputArray = @($input)
                    $TempPolicyPath = $InputArray[0]
                    $PSModuleRoot = $InputArray[1]
                    $DoNotCacheRecommended = $InputArray[2]
                    $IsVerbose = $InputArray[3]
                    
                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        $usermoderules = Get-UserModeBlockRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                        
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $usermoderules -ErrorAction Stop | Out-Null;
                    } catch {
                        Write-Error $_
                        return $false
                    }
                    
                    return $true
                }

                $UserModeBlockRulesTaskResult = $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference | Powershell $UserModeBlockRulesTask

                if (-not $UserModeBlockRulesTaskResult) {
                    throw "Unable to merge with user mode block rules. Error occurred."
                }

                $AppendedZeroes = Update-CommentsMapWithUnderscores -IDsAndComments $IDsAndComments -ErrorAction Stop
                Add-WDACRuleComments -IDsAndComments $AppendedZeroes -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = New-CommentMap -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $TempPolicyPath -ErrorAction Stop
            }

            if ($DefaultWindowsMode) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                
                $WindowsModeScriptBlock = {
                    
                    $InputArray = @($input)
                    $TempPolicyPath = $InputArray[0]
                    $PSModuleRoot = $InputArray[1]
                    $DoNotCacheRecommended = $InputArray[2]
                    $IsVerbose = $InputArray[3]

                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        $rules = Get-WindowsModeRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                        
                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $rules -ErrorAction Stop | Out-Null;
                    } catch {
                        Write-Error ($_ | Format-List * -Force | Out-String)
                        return $false
                    }

                    return $true
                }

                $WindowModeResult = $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference | PowerShell $WindowsModeScriptBlock
                
                if (-not ($WindowModeResult)) {
                    throw "Unable to merge with Default Windows Mode rules. Error occurred."
                }

                $AppendedZeroes = Update-CommentsMapWithUnderscores -IDsAndComments $IDsAndComments -ErrorAction Stop
                Add-WDACRuleComments -IDsAndComments $AppendedZeroes -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = New-CommentMap -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $TempPolicyPath -ErrorAction Stop
            }

            if ($AllowMicrosoftMode) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(

                $AddMicrosoftModeScriptBlock = {

                    $InputArray = @($input)
                    $TempPolicyPath = $InputArray[0]
                    $PSModuleRoot = $InputArray[1]
                    $DoNotCacheRecommended = $InputArray[2]
                    $IsVerbose = $InputArray[3]
                    
                    try {
                        Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1") -ErrorAction Stop;
                        $rules = Get-AllowMicrosoftModeRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;

                        Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $rules -ErrorAction Stop | Out-Null;
                    } catch {
                        Write-Error ($_ | Format-List * -Force | Out-String)
                        return $false
                    }

                    return $true
                }

                $AddMicrosoftModeResult = $TempPolicyPath,$PSModuleRoot,$DoNotCacheRecommended.ToBool(),$VerbosePreference | PowerShell $AddMicrosoftModeScriptBlock

                if (-not $AddMicrosoftModeResult) {
                    throw "Unable to merge with Microsoft Mode rules. Error occurred."
                }

                $AppendedZeroes = Update-CommentsMapWithUnderscores -IDsAndComments $IDsAndComments -ErrorAction Stop
                Add-WDACRuleComments -IDsAndComments $AppendedZeroes -FilePath $TempPolicyPath -ErrorAction Stop
                $IDsAndComments = New-CommentMap -FilePath $TempPolicyPath
                $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $TempPolicyPath -ErrorAction Stop
            }

            function Set-RepairedIDsAfterNewSigner {
            #Since _0 or _1 is added to the end of each ID following Add-SignerRule, we need to modify things slightly 
            #...for the Remove-UnderscoreDigits function to work
                [CmdletBinding()]
                Param (
                    [ValidateNotNullOrEmpty()]
                    [string]$Comment,
                    [ValidateNotNullOrEmpty()]
                    [string]$FilePath,
                    $IDsAndComments
                )

                $TempRulesAddSigner = Get-CIPolicy -FilePath $FilePath -ErrorAction Stop
                $NewSignerIDs = @()
                foreach ($tempRule in $TempRulesAddSigner) {
                    if (($tempRule.Id.Substring($tempRule.Id.Length -2)) -match "_1") {
                    #The newly-added signer rules will be the only ones with _1 at the end of the ID
                        $NewSignerIDs += $tempRule.Id
                    }
                }

                $FileContent = Get-Content $FilePath -ErrorAction Stop
                foreach ($NewSignerID in $NewSignerIDs) {
                    $NewID = IncrementSignerID -RuleMap $IDsAndComments -ErrorAction Stop
                    $IDsAndComments += @{$NewID = $Comment}
                    
                    #We add an extra _1 to the ID here because it will be removed by Remove-UnderscoreDigits
                    $FileContent = $FileContent.Replace($NewSignerID,($NewID + "_1"))
                }
                $FileContent | Set-Content $FilePath -Force -ErrorAction Stop

                Remove-UnderscoreDigits -FilePath $FilePath -ErrorAction Stop
                return $IDsAndComments
            }

            #Add Code Signing / Policy Signing Rules: =====================================================================
            if ($AddPSCodeSigner) {
                Export-CodeSignerAsCER -Destination (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -PSCodeSigner -ErrorAction Stop | Out-Null

                Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -User -Kernel -ErrorAction Stop
                $IDsAndComments = Set-RepairedIDsAfterNewSigner -Comment "Powershell Code Signing Certificate" -FilePath $TempPolicyPath -IDsAndComments $IDsAndComments -ErrorAction Stop
                $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            }

            if ($UpdatePolicySigner -or ($SupplementalPolicySigner -and (-not $IsSupplemental))) {
                Export-CodeSignerAsCER -Destination (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -WDACCodeSigner -ErrorAction Stop | Out-Null
                if ($UpdatePolicySigner) {
                    Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Update -ErrorAction Stop
                    $IDsAndComments = Set-RepairedIDsAfterNewSigner -Comment "WDAC Update Certificate" -FilePath $TempPolicyPath -IDsAndComments $IDsAndComments -ErrorAction Stop
                } 
                if ($SupplementalPolicySigner -and (-not $IsSupplemental)) {
                    Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Supplemental -ErrorAction Stop
                    $IDsAndComments = Set-RepairedIDsAfterNewSigner -Comment "WDAC Supplemental Signer Certificate" -FilePath $TempPolicyPath -IDsAndComments $IDsAndComments -ErrorAction Stop
                }
                $IDsAndComments = Update-NewIDs -IDsAndComments $IDsAndComments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            }
            #=============================================================================================================

        #Apply Policy Options ======================================================
        #This is slightly different from "New-WDACPolicy" in that if a flag isn't set, a rule is not specified, it is not removed or added 
        #...(hence the "elseifs" instead of just "else")
    
            #Case 0: 'Enabled:UMCI'
            if ($UMCI -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 0
            } elseif ($RemoveUMCI) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 0 -Delete
            }

            #Case 1: 'Enabled:Boot Menu Protection'
            if ($BootMenuProtection -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 1
            } elseif ($RemoveBootMenuProtection) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 1 -Delete
            }

            #Case 2: 'Required:WHQL'
            if ($WHQL -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 2
            } elseif ($RemoveWHQL) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 2 -Delete
            }

            #Case 3: 'Enabled:Audit Mode'
            if ($Audit -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 3
            } elseif ($RemoveAudit) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 3 -Delete
            }

            #Case 4: 'Disabled:Flight Signing'
            if ($DisableFlightSigning -and (-not $IsSupplemental)) {
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
            if ($AdvancedBootOptionsMenu -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 9
            } elseif ($RemoveAdvancedBootOptionsMenu) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 9 -Delete
            }

            #Case 10: 'Enabled:Boot Audit On Failure'
            if ($BootAuditOnFailure -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 10
            } elseif ($RemoveBootAuditOnFailure) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 10 -Delete
            }

            #Case 11: 'Disabled:Script Enforcement'
            if ($DisableScriptEnforcement -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 11
            } elseif ($RemoveDisableScriptEnforcement) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 11 -Delete
            }

            #Case 12: 'Required:Enforce Store Applications'
            if ($EnforceStoreApps -and (-not $IsSupplemental)) {
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
            if ($InvalidateEAsOnReboot -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 15
            } elseif ($RemoveInvalidateEAsOnReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 15 -Delete
            }

            #Case 16:'Enabled:Update Policy No Reboot'
            if ($UpdatePolicyNoReboot -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 16
            } elseif ($RemoveUpdatePolicyNoReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 16 -Delete
            }

            #Case 17:'Enabled:Allow Supplemental Policies'
            if ($AllowSupplementalPolicies -and (-not $IsSupplemental)) {
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
            if ($DynamicCodeSecurity -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 19
            } elseif ($RemoveDynamicCodeSecurity) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 19 -Delete
            }

            #Case 20:'Enabled:Revoked Expired As Unsigned'
            if ($TreatRevokedAsUnsigned -and (-not $IsSupplemental)) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 20
            } elseif ($RemoveTreatRevokedAsUnsigned) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 20 -Delete
            }

            #Case HVCI: Whether HVCI is enabled
            if ($HVCI) {
                Set-HVCIOptions -Enabled -FilePath $TempPolicyPath
                $HVCIOption = 1
            } elseif ($RemoveHVCI) {
                Set-HVCIOptions -None -FilePath $TempPolicyPath
                $HVCIOption = 0
            } elseif ($StrictHVCI) {
                Set-HVCIOptions -Strict -FilePath $TempPolicyPath
                $HVCIOption = 2
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
                
                if ($Signed) {
                    if (-not (Set-WDACPolicySigned -PolicyGUID $PolicyGUID -Set -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to update IsSigned attribute for policy $PolicyGUID"
                    }
                } elseif ($Unsigned) {
                    if (-not (Set-WDACPolicySigned -PolicyGUID $PolicyGUID -Unset -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to update IsSigned attribute to FALSE for policy $PolicyGUID"
                    }
                }

                if ($Audit) {
                    if (-not (Set-WDACPolicyEnforced -PolicyGUID $PolicyGUID -Unset -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to update AuditMode attribute for policy $PolicyGUID"
                    }
                } elseif ($RemoveAudit) {
                    if (-not (Set-WDACPolicyEnforced -PolicyGUID $PolicyGUID -Set -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to update AuditMode attribute to FALSE for policy $PolicyGUID"
                    }
                }

                if ($Pillar) {
                    if (-not (Set-WDACPolicyPillar -PolicyGUID $PolicyGUID -Set -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to update IsPillar attribute for policy $PolicyGUID"
                    }
                } elseif ($RemovePillar) {
                    if (-not (Set-WDACPolicyPillar -PolicyGUID $PolicyGUID -Unset -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to update IsPillar attribute to FALSE for policy $PolicyGUID"
                    }
                }

                if (Test-WDACPolicySigned -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) {
                    if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $PolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Signed -Connection $Connection -ErrorAction Stop)) {
                        throw "Could not set LastSignedVersion attribute on Policy $PolicyGUID"
                    }
                } else {
                    if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $PolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Unsigned -Connection $Connection -ErrorAction Stop)) {
                        throw "Could not set LastUnsignedVersion attribute on Policy $PolicyGUID"
                    }
                }

                try {
                    if ($HVCIOption) {
                        if ( (Get-HVCIPolicySetting -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -ne $HVCIOption) {
                            Set-HVCIPolicySetting -PolicyGUID $PolicyGUID -HVCIOption $HVCIOption -Connection $Connection -ErrorAction Stop
                        }
                    }
                } catch {
                    Write-Warning $_
                }

                $Transaction.Commit()
                Write-Host "Successfully committed changes to Policy $PolicyGUID" -ForegroundColor Green
                if ($PSModuleRoot) {
                    if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer")) {
                        Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -Force -ErrorAction SilentlyContinue
                    }
            
                    if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer")) {
                        Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Force -ErrorAction SilentlyContinue
                    }
                }
                if ($TempPolicyPath) {
                    if (Test-Path $TempPolicyPath) {
                        Remove-Item $TempPolicyPath -Force -ErrorAction SilentlyContinue
                    }
                }
                if ($BackupPolicyLocation -and (Test-Path $BackupPolicyLocation)) {
                    Remove-Item $BackupPolicyLocation -Force -ErrorAction SilentlyContinue
                }
                $Connection.Close()
            } else {
                $Transaction.Rollback()
                $Connection.Close()
                Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue
                throw "Unable to retrieve version information regarding a policy from the database."
            }

    } catch {
        $theError = $_

        if ($TempPolicyPath) {
            if (Test-Path $TempPolicyPath) {
                Remove-Item $TempPolicyPath -Force
            }
        }

        if ($Transaction -and $Connection) {
            if ($Connection.AutoCommit -eq $false) {
                $Transaction.Rollback()
            }
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

        if ($BackupPolicyLocation -and $OldPolicyPath -and (Test-Path $BackupPolicyLocation)) {
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

Export-ModuleMember -Function Edit-WDACPolicy