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

function Test-ValidP7SignedFile {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SignTool
    )

    #See if the pkcs7 certificate is parsed successfully
    $CertUtilResult = certutil.exe -asn $Path | Out-String

    if ($CertUtilResult -match "CertUtil: -asn command completed successfully.") {
    
        #Verify that the signature is valid
        $VerifySignatureResult = cmd.exe /c "`"$SignTool`" verify /p7 /v /debug `"$Path`"" 2>&1
        $theError = $VerifySignatureResult | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
        if ($VerifySignatureResult -contains "Successfully verified: $Path" -and (-not $theError)) {
            return $true
        } else {
            throw ($theError + ". $Path is not a valid signed WDAC policy file.")
        }
    } else {
        $theError = ""
        if ($CertUtilResult -match "(?<=CertUtil\:\s?(\-asn) command FAILED\:\s?).*") {
            $theError = $Matches[0]
        }
        throw ($theError + ". Signed P7 file not encoded correctly, or some other error, or output of certutil has been modified since module release.")
    }
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
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$CIPPolicyPath,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DestinationDirectory
    )
    
    try {
        $WDACodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
        if (-not $WDACodeSigningCert -or "" -eq $WDACodeSigningCert) {
            throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
        } elseif (-not ($WDACodeSigningCert.ToLower() -match "cert\:\\")) {
            throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
        }
        $cert = Get-ChildItem -Path $WDACodeSigningCert -ErrorAction Stop
        
        $SignTool = (Get-LocalStorageJSON -ErrorAction Stop)."SignTool"
        if (-not $SignTool -or ("" -eq $SignTool) -or ("Full_Path_To_SignTool.exe" -eq $SignTool)) {
            throw "Error: Empty, default, or null value for WDAC Policy signing certificate retreived from Local Storage."
        } elseif (-not (Test-Path $SignTool)) {
            throw "Path for Sign tool does not exist or not a valid path."
        }

        $cert_subject = $cert.Subject
        
        if ($cert_subject -match "(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))") {
            $cert_subject = $Matches[0]
        } else {
            throw "WDACCodeSigningCert subject name not in the correct format. Example: CN=WDACSigningCertificate "
        }

        Start-Process $SignTool -ArgumentList 'sign', '/v' , '/n', "`"$cert_subject`"", '/p7', "`"$DestinationDirectory`"", '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'sha256', "`"$CIPPolicyPath`"" -Wait -NoNewWindow -ErrorAction Stop | Out-Null
        
        $ResultSignedPath = ( (Join-Path $DestinationDirectory -ChildPath (Split-Path $CIPPolicyPath -Leaf)) + ".p7")

        if ( (Test-ValidP7SignedFile -Path $ResultSignedPath -SignTool $SignTool -ErrorAction Stop) -eq $true) {
            return $ResultSignedPath
        } else {
            throw "$ResultSignedPath is not a valid signed file."
        }
    } catch {
        throw $_
    }
}


