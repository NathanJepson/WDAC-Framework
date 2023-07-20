if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\JSON-LocalStorageTools.psm1")
}

function Export-CodeSignerAsCER {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $Destination,
        [switch]$PSCodeSigner,
        [switch]$WDACCodeSigner
    )

    if ($PSCodeSigner) {
        try {
            $PSCodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."PowerShellCodeSigningCertificate"
            if (-not $PSCodeSigningCert -or "" -eq $PSCodeSigningCert) {
                throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
            } elseif (-not ($PSCodeSigningCert.ToLower() -match "cert\:\\")) {
                throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            }
            $cert = Get-ChildItem -Path $PSCodeSigningCert
            Export-Certificate -Cert $cert -FilePath (Join-Path -Path $Destination -ChildPath "PSCodeSigning.cer")
            
        } catch {
            throw $_
        }
    }

    if ($WDACCodeSigner) {
        try {
            $WDACodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
            if (-not $WDACodeSigningCert -or "" -eq $WDACodeSigningCert) {
                throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
            } elseif (-not ($WDACodeSigningCert.ToLower() -match "cert\:\\")) {
                throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            }
            $cert = Get-ChildItem -Path $WDACodeSigningCert
            Export-Certificate -Cert $cert -FilePath (Join-Path -Path $Destination -ChildPath "WDACCodeSigning.cer")
        } catch {
            throw $_
        }
    }
}
function Invoke-SignTool {
    [CmdletBinding()]
    Param ()
    #TODO
}


