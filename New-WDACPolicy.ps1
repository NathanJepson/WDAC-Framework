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
    Creates a new signer rule for updating this policy--the signer rule referencing the WDAC policy code signing certificate (i.e., the WDACPolicySigningCertificate in LocalStorage.json)

    .PARAMETER SupplementalPolicySigner
    Creates a new signer rule for adding signed supplemental policies--the signer rule referencing the WDAC policy code signing certificate (i.e., the WDACPolicySigningCertificate in LocalStorage.json)

    .PARAMETER DoNotCacheRecommended
    When this is set, Microsoft's recommended policy rules will be purged (not stored locally after pulling from Github)

    .PARAMETER DenyByDefaultPolicy

    .PARAMETER AllowByDefaultPolicy

    .PARAMETER DriverBlockRules

    .PARAMETER OtherBlockRules

    .PARAMETER DefaultWindowsMode

    .PARAMETER AllowMicrosoftMode

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
        [switch]$ISG,
        [switch]$InvalidateEAsOnReboot,
        [switch]$UpdatePolicyNoReboot,
        [switch]$AllowSupplementalPolicies,
        [switch]$DisableRuntimeFilepathRules,
        [switch]$DynamicCodeSecurity,
        [switch]$TreatRevokedAsUnsigned
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
                    $SupplementalPolicySigner = $true
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

            if (-not $WorkingPoliciesLocation -or -not $WorkingPoliciesLocationType) {
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
                    throw "Error: Empty or null value for signing certificate retreived from Local Storage."
                } elseif (-not ($WDACodeSigner.ToLower() -match "cert\:\\")) {
                    throw "Local cache does not specify a valid certificate path for the signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
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
    }
}