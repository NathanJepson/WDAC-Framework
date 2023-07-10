function New-WDACPolicy {
    <#
    .SYNOPSIS
    Creates a new WDAC policy .XML file and places it in the working policies directory.

    .DESCRIPTION
    Create a WDAC policy based on user supplied parameters including merging with Microsoft-recommended block rules as well
    as setting other policy options. Does not generate the resultant .cip file (that is accomplished by "Deploy-WDACPolicies").
    Adds important information about this policy to the trust database. 

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER Pillar
    When this flag is set, you specify that you want the policy to be a pillar--that is, a base policy which is applied to every computer irrespective of group membership.

    .PARAMETER PolicyName
    Specify the name of the policy as a string. (Required.) You must use valid characters which can be part of a file path / file name.

    .PARAMETER FilePath
    If you have already created the WDAC policy XML file and just want to set some options, specify its filepath with this.

    .PARAMETER BasePolicyID
    If you are creating a supplemental policy, then specify the BasePolicyID (otherwise it must be pulled from the .xml file designated by FilePath)

    .PARAMETER AddPSCodeSigner
    Adds a new signer rule for the PowerShell code signing certificate to this new WDAC policy.

    .PARAMETER UpdatePolicySigner
    Creates a new signer rule for the WDAC Policy Signing certificate--for updating this policy--obtained from LocalStorage.json (i.e., the WDACPolicySigningCertificate)

    .PARAMETER SupplementalPolicySigner
    Creates a new signer rule for the WDAC Policy Signing certificate--for signing a supplemental policy--obtained from LocalStorage.json (i.e., the WDACPolicySigningCertificate)

    .PARAMETER DoNotCacheRecommended
    When this is set, Microsoft's recommended policy rules will be purged (not stored locally after pulling from Github)

    .PARAMETER DenyByDefaultPolicy
    This policy will deny apps by default.

    .PARAMETER AllowByDefaultPolicy
    This policy will allow apps by default.

    .PARAMETER DriverBlockRules
    When this is set, this policy will be merged with Microsoft's recommended driver block rules.

    .PARAMETER OtherBlockRules
    When this is set, this policy will be merged with Microsoft's recommended user mode block rules.

    .PARAMETER DefaultWindowsMode
    When this is set, the policy will be merged with the Default Windows Mode WDAC policy provided by Microsoft.

    .PARAMETER AllowMicrosoftMode
    When this is set, the policy will be merged with the Allow Microsoft Mode WDAC policy provided by Microsoft.

    .PARAMETER Supplemental

    .PARAMETER Signed

    .PARAMETER Unsigned

    .PARAMETER Audit

    .PARAMETER Enforced

    .PARAMETER UMCI

    .PARAMETER BootMenuProtection

    .PARAMETER WHQL

    .PARAMETER DisableFlightSigning

    .PARAMETER InheritDefaultPolicy

    .PARAMETER AllowDebugPolicyAugmented

    .PARAMETER RequireEVSigners

    .PARAMETER AdvancedBootOptionsMenu

    .PARAMETER BootAuditOnFailure

    .PARAMETER DisableScriptEnforcement

    .PARAMETER EnforceStoreApps

    .PARAMETER EnableManagedInstaller

    .PARAMETER ISG

    .PARAMETER InvalidateEAsOnReboot

    .PARAMETER UpdatePolicyNoReboot

    .PARAMETER AllowSupplementalPolicies

    .PARAMETER DisableRuntimeFilepathRules

    .PARAMETER DynamicCodeSecurity

    .PARAMETER TreatRevokedAsUnsigned

    .EXAMPLE
    ()

    .EXAMPLE
    ()

    .EXAMPLE
    ()
    #>

    [CmdletBinding()]
    Param (
        [ValidateScript({-not $Supplemental}, ErrorMessage = "A policy cannot be both a supplemental policy and a Pillar.")]
        [switch]$Pillar,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
        [string]$FilePath,
        [string]$BasePolicyID,
        [switch]$AddPSCodeSigner,
        [switch]$UpdatePolicySigner,
        [switch]$SupplementalPolicySigner,
        [Alias("NoCache")]
        [switch]$DoNotCacheRecommended,
        [Alias("Deny")]
        [ValidateScript({-not $AllowByDefaultPolicy}, ErrorMessage = "Cannot have both an allow-by-default and a deny-by-default policy.")]
        [switch]$DenyByDefaultPolicy,
        [Alias("Allow")]
        [ValidateScript({-not $DenyByDefaultPolicy}, ErrorMessage = "Cannot have both an allow-by-default and a deny-by-default policy.")]
        [switch]$AllowByDefaultPolicy,
        [switch]$DriverBlockRules,
        [Alias("UserModeBlockRules")]
        [switch]$OtherBlockRules,
        [Alias("Windows")]
        [switch]$DefaultWindowsMode,
        [Alias("Microsoft")]
        [switch]$AllowMicrosoftMode,
        [ValidateScript({-not $Pillar}, ErrorMessage = "A policy cannot be both a supplemental policy and a Pillar.")]
        [switch]$Supplemental,
        [ValidateScript({-not $Unsigned}, ErrorMessage = "A policy cannot be both signed and unsigned. You cannot serve two masters.")]
        [switch]$Signed,
        [ValidateScript({-not $Signed}, ErrorMessage = "A policy cannot be both signed and unsigned. You cannot serve two masters.")]
        [switch]$Unsigned,
        [ValidateScript({-not $Enforced}, ErrorMessage = "A policy cannot be both an Audit policy and an Enforced policy. This is according to Plato's Law of non-contradiction. The philosphers are laughing you to scorn.")]
        [switch]$Audit,
        [ValidateScript({-not $Audit}, ErrorMessage = "A policy cannot be both an Audit policy and an Enforced policy. This is according to Plato's Law of non-contradiction. The philosphers are laughing you to scorn.")]
        [switch]$Enforced,
        [Alias("UserModeCodeIntegrity")]
        [switch]$UMCI,
        [switch]$BootMenuProtection,
        [switch]$WHQL,
        [switch]$DisableFlightSigning,
        [switch]$InheritDefaultPolicy,
        [switch]$AllowDebugPolicyAugmented,
        [switch]$RequireEVSigners,
        [switch]$AdvancedBootOptionsMenu,
        [switch]$BootAuditOnFailure,
        [switch]$DisableScriptEnforcement,
        [Alias("Store")]
        [switch]$EnforceStoreApps,
        [switch]$EnableManagedInstaller,
        [Alias("IntelligentSecurityGraph")]
        [switch]$ISG,
        [switch]$InvalidateEAsOnReboot,
        [switch]$UpdatePolicyNoReboot,
        [switch]$AllowSupplementalPolicies,
        [switch]$DisableRuntimeFilepathRules,
        [switch]$DynamicCodeSecurity,
        [switch]$TreatRevokedAsUnsigned,
        [switch]$HVCI
    )

    begin {
        if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
            $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
            Write-Verbose "The current file is in the SignedModules folder."
        } else {
            $PSModuleRoot = $PSScriptRoot
        }

        if ($Supplemental -and ($DenyByDefaultPolicy -or $AllowByDefaultPolicy)) {
            throw "Error: Allow-by-default or deny-by-default is inherited from the base policy when -supplemental is set."
        }

        if (-not $DenyByDefaultPolicy -and -not $AllowByDefaultPolicy -and (-not $Supplemental)) {
            throw "You must set either `"-DenyByDefaultPolicy`" or `"-AllowByDefaultPolicy`" "
        }

        if ($AllowDebugPolicyAugmented -or $RequireEVSigners) {
            throw "`"Debug Policy Augmented`" or `"Require EV Signers`" is not yet supported by Microsoft."
        }

        if ($Supplemental -and (-not $FilePath -and -not $BasePolicyID)) {
        #TODO: Give the user a list of vaild Base Policy IDs from the database
            throw "Please provide the BasePolicy ID"
        }
        
        if (-not $Signed -and -not $Unsigned) {
        #Unsigned policy is the default
            $Unsigned = $true
        }

        if (-not $Audit -and -not $Enforced) {
        #Audit policy is the default
            $Audit = $true
        }

        $WDACCodeSigner = $null

        if ($Signed) {
            
            if (-not $UpdatePolicySigner -and -not $SupplementalPolicySigner) {
            #For a signed policy, the default behavior is to add both a supplemental and an update policy signer
                $UpdatePolicySigner = $true
                if ($AllowSupplementalPolicies) {
                    $SupplementalPolicySigner = $true #TODO: Is this option able to be enabled for a supplemental policy without breaking anything?
                }
            }
        } else {
            if ($UpdatePolicySigner -or $SupplementalPolicySigner) {
                throw "-UpdatePolicySigner and -SupplementalPolicySigner are only valid options for a signed policy (i.e., the -Signed flag is set.)"
            }
        }
    }

    process {

        try {
            $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
            $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"

            if (-not $WorkingPoliciesLocation -or -not $WorkingPoliciesLocationType -or "" -eq $WorkingPoliciesLocation -or "" -eq $WorkingPoliciesLocationType) {
                throw "Null or invalid values provided for Working Policies location (or the location type)"
            }
        } catch {
            Write-Verbose $_
            throw "Trouble in retrieving your working policies location."
            return
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
                Write-Error $_
                return;
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
                Write-Error $_
                return;
            }
        }

        try {
            if (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop) {
                throw "A policy with the name $PolicyName already exists."
            }
        } catch {
            Write-Verbose $_
            throw "Failed to import Sqlite OR a problem with connecting to the trust database."
        }

        $TempPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$PolicyName.xml")

        if (Test-Path $TempPolicyPath) {
            try {
                Remove-Item $TempPolicyPath -Force -ErrorAction Stop
            } catch {
                $RandomGUID = New-Guid
                $TempPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$($PolicyName)_$RandomGUID.xml")
            }
        }

        try {
            if ($FilePath) {
                Copy-Item $FilePath -Destination $TempPolicyPath -Force
            } elseif ($Supplemental) {
                Copy-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\SupplementalShell.xml") -Destination $TempPolicyPath -Force
            } elseif ($AllowByDefaultPolicy) {
                Copy-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\AllowAll.xml") -Destination $TempPolicyPath -Force
            } elseif ($DenyByDefaultPolicy) {
                Copy-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\DenyAllAudit.xml") -Destination $TempPolicyPath -Force
            } 

            if (-not $FilePath) {
            #Only reset the policy ID if the filepath to a policy isn't already provided. I may change this behavior later.
                if ($Supplemental) {
                    $PolicyID = Set-CIPolicyIdInfo -FilePath $TempPolicyPath -ResetPolicyID -PolicyName $PolicyName -SupplementsBasePolicyID $BasePolicyID -ErrorAction Stop
                } else {
                    $PolicyID = Set-CIPolicyIdInfo -FilePath $TempPolicyPath -ResetPolicyID -PolicyName $PolicyName -ErrorAction Stop
                }
            }

            if ($DriverBlockRules) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                PowerShell {
                    [CmdletBinding()]
                    Param(
                        $TempPolicyPath,
                        $PSModuleRoot,
                        $DenyByDefaultPolicy,
                        $DoNotCacheRecommended,
                        $IsVerbose
                    )

                    Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1");
                    $driverrules = Get-DriverBlockRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                    if ($DenyByDefaultPolicy) {
                    #Remove the rule with the asterisk if it is a deny by default policy
                        $driverrules = $driverrules | Where-Object {-not ($_.attributes["FileName"] -eq "*")}
                    }
                    Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $driverrules -ErrorAction Stop | Out-Null;
                } -args $TempPolicyPath,$PSModuleRoot,$DenyByDefaultPolicy,$DoNotCacheRecommended.ToBool(),$VerbosePreference
            }

            if ($OtherBlockRules) {
            #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
                PowerShell {
                    [CmdletBinding()]
                    Param(
                        $TempPolicyPath,
                        $PSModuleRoot,
                        $DenyByDefaultPolicy,
                        $DoNotCacheRecommended,
                        $IsVerbose
                    )
                    
                    Import-Module (Join-Path -Path $PSModuleRoot -ChildPath ".\Resources\Microsoft-Recommended-Rules.psm1");
                    $usermoderules = Get-UserModeBlockRules -DoNotCacheRecommended $DoNotCacheRecommended -ErrorAction Stop -Verbose:$IsVerbose;
                    if ($DenyByDefaultPolicy) {
                    #Remove the rule with the asterisk if it is a deny by default policy
                        $usermoderules = $usermoderules | Where-Object {-not ($_.attributes["FileName"] -eq "*")}
                    }
                    Merge-CIPolicy -OutputFilePath $TempPolicyPath -PolicyPaths $TempPolicyPath -Rules $usermoderules -ErrorAction Stop | Out-Null;
                } -args $TempPolicyPath,$PSModuleRoot,$DenyByDefaultPolicy,$DoNotCacheRecommended.ToBool(),$VerbosePreference
            }

            if ($DefaultWindowsMode) {
            #TODO
            }

            if ($AllowMicrosoftMode) {
            #TODO
            }

            #Add Code Signing / Policy Signing Rules: =====================================================================
            if ($AddPSCodeSigner) {
                Export-CodeSignerAsCER -Destination (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -PSCodeSigner -ErrorAction Stop | Out-Null
                Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -User -Kernel -ErrorAction Stop
            }

            if ($UpdatePolicySigner -or $SupplementalPolicySigner) {
                Export-CodeSignerAsCER -Destination (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -WDACCodeSigner -ErrorAction Stop | Out-Null
                if ($UpdatePolicySigner) {
                    Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Update -ErrorAction Stop
                } 
                if ($SupplementalPolicySigner) {
                    Add-SignerRule -FilePath $TempPolicyPath -CertificatePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Supplemental -ErrorAction Stop
                }
            }
            #==============================================================================================================


            #Apply Policy Options ======================================================
            #Case 0: 'Enabled:UMCI'
            if ($UMCI) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 0
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 0 -Delete
            }
            #Case 1: 'Enabled:Boot Menu Protection'
            if ($BootMenuProtection) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 1
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 1 -Delete
            }
            #Case 2: 'Required:WHQL'
            if ($WHQL) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 2
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 2 -Delete
            }
            #Case 3: 'Enabled:Audit Mode'
            if ($Audit) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 3
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 3 -Delete
            }
            #Case 4: 'Disabled:Flight Signing'
            if ($DisableFlightSigning) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 4
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 4 -Delete
            }
            #Case 5: 'Enabled:Inherit Default Policy'
            if ($InheritDefaultPolicy) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 5
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 5 -Delete
            }
            #Case 6: 'Enabled:Unsigned System Integrity Policy'
            if ($Unsigned) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 6
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 6 -Delete
            }
            
            #Case 7: 'Allowed:Debug Policy Augmented'
            #Not yet supported by Microsoft

            #Case 8: 'Required:EV Signers'
            #Not yet supported by Microsoft

            #Case 9: 'Enabled:Advanced Boot Options Menu'
            if ($AdvancedBootOptionsMenu) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 9
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 9 -Delete
            }
            #Case 10: 'Enabled:Boot Audit On Failure'
            if ($BootAuditOnFailure) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 10
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 10 -Delete
            }
            #Case 11: 'Disabled:Script Enforcement'
            if ($DisableScriptEnforcement) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 11
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 11 -Delete
            }
            #Case 12: 'Required:Enforce Store Applications'
            if ($EnforceStoreApps) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 12
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 12 -Delete
            }
            #Case 13: 'Enabled:Managed Installer'
            if ($EnableManagedInstaller) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 13
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 13 -Delete
            }
            #Case 14:'Enabled:Intelligent Security Graph Authorization'
            if ($ISG) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 14
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 14 -Delete
            }
            #Case 15:'Enabled:Invalidate EAs on Reboot'
            if ($InvalidateEAsOnReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 15
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 15 -Delete
            }
            #Case 16:'Enabled:Update Policy No Reboot'
            if ($UpdatePolicyNoReboot) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 16
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 16 -Delete
            }
            #Case 17:'Enabled:Allow Supplemental Policies'
            if ($AllowSupplementalPolicies) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 17
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 17 -Delete
            }
            #Case 18:'Disabled:Runtime FilePath Rule Protection'
            if ($DisableRuntimeFilepathRules) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 18
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 18 -Delete
            }
            #Case 19:'Enabled:Dynamic Code Security'
            if ($DynamicCodeSecurity) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 19
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 19 -Delete
            }
            #Case 20:'Enabled:Revoked Expired As Unsigned'
            if ($TreatRevokedAsUnsigned) {
                Set-RuleOption -FilePath $TempPolicyPath -Option 20
            } else {
                Set-RuleOption -FilePath $TempPolicyPath -Option 20 -Delete
            }
            #Case HVCI: Whether HVCI is enabled
            if ($HVCI) {
                Set-HVCIOptions -Enabled -FilePath $TempPolicyPath
            } else {
                #TODO: Provide an option to set the -strict flag (which will set it to "2")
            }
            #===========================================================================

            #TODO: Add Policy Information to the database

        } catch {
            Write-Error $_
            return
        }

        try {
            [xml]$PolicyXML = Get-Content -Path $TempPolicyPath
            $VerisonNumber = $PolicyXML.SiPolicy.VersionEx
            $NewFileName = ($PolicyName + "_v" + ($VerisonNumber.replace('.','_')) + ".xml")
            if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
                Copy-Item $TempPolicyPath -Destination (Join-Path $WorkingPoliciesLocation -ChildPath $NewFileName) -Force -ErrorAction Stop
            } else {
            #TODO: Other working policies directory types
            }
        } catch {
            Write-Verbose $_
            throw "There was a problem placing the new policy file into your working policies directory."
            return
        }

        Write-Verbose "Policy creation successful."
    }

    end {
        if ($TempPolicyPath) {
            if (Test-Path $TempPolicyPath) {
                Remove-Item $TempPolicyPath -Force
            }
        }

        if ($PSModuleRoot) {
            if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer")) {
                Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\PSCodeSigning.cer") -Force
            }
    
            if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer")) {
                Remove-Item (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\WDACCodeSigning.cer") -Force
            }
        }
    }
}