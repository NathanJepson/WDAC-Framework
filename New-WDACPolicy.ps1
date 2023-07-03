function New-WDACPolicy {
    <#
    .SYNOPSIS
    Creates a new WDAC policy .XML file and places it in the working policies directory (and its parent directory if applicable)

    .DESCRIPTION
    Create a WDAC policy based on user supplied parameters including merging with Microsoft-recommended block rules as well
    as setting other policy options. Does not generate the resultant .cip file (that is accomplished by "Deploy-WDACPolicies").
    Adds important information about this policy to the trust database. 

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER Pillar
    ()

    .EXAMPLE
    ()

    .EXAMPLE
    ()

    .EXAMPLE
    ()
    #>

    [CmdletBinding()]
    Param (
        [switch]$Pillar,
        [switch]$AddPSCodeSigner,
        [switch]$DenyByDefaultPolicy,
        [switch]$AllowByDefaultPolicy,
        [switch]$DriverBlockRules,
        [swtich]$OtherBlockRules,
        [switch]$DefaultWindowsMode,
        [switch]$AllowMicrosoftMode,
        [switch]$Supplemental,
        [switch]$Signed,
        [switch]$Unsigned,
        [switch]$Audit,
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
        [switch]$EnforceStoreApps,
        [switch]$EnableManagedInstaller,
        [switch]$ISG,
        [switch]$InvalidateEAsOnReboot,
        [switch]$UpdatePolicyNoReboot,
        [switch]$AllowSupplementalPolicies,
        [switch]$DisableRuntimeFilepathRules,
        [switch]$DynamicCodeSecurity,
        [switch]$TreatRevokedAsUnsigned,
        [string]$PolicyName,
        [string]$BasePolicyID
    )

    begin {
        if ($DenyByDefaultPolicy -and $AllowByDefaultPolicy) {
            throw "Cannot have both an allow-by-default and a deny-by-default policy."
        } elseif (-not $DenyByDefaultPolicy -and -not $AllowByDefaultPolicy -and (-not $Supplemental)) {
            throw "You must set either `"-DenyByDefaultPolicy`" or `"-AllowByDefaultPolicy`" "
        }

        if ($AllowDebugPolicyAugmented -or $RequireEVSigners) {
            throw "`"Debug Policy Augmented`" or `"Require EV Signers`" is not yet supported by Microsoft."
        }
        if ($Pillar -and $Supplemental) {
            throw "A policy cannot be both a supplemental policy and a Pillar."
        }
        if ($Signed -and $Unsigned) {
            throw "A policy cannot be both signed and unsigned. You cannot serve two masters."
        } elseif (-not $Signed -and -not $Unsigned) {
        #Unsigned policy is the default
            $Unsigned = $true
        }
        if ($Audit -and $Enforced) {
            throw "A policy cannot be both an Audit policy and an Enforced policy. This is according to Plato's Law of non-contradiction. The philosphers are laughing you to scorn."
        } elseif (-not $Audit -and -not $Enforced) {
        #Audit policy is the default
            $Audit = $true
        }

        $WDACCodeSigner = $null

        if ($Signed) {
            try {
                $WDACodeSigner = (Get-LocalStorageJSON)."WDACPolicySigningCertificate"
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
    }

    process {
            
    }

    end {
        Write-Verbose "Policy creation successful."
    }
}