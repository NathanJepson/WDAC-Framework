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

function Select-WDACCertificateToUse {
    [CmdletBinding()]
    param (
        $WDACCodeSigningCert,
        $WDACCodeSigningCert2,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $PartialPrompt
    )

    $result = $null
    if ((Test-Path $WDACCodeSigningCert) -and (Test-Path $WDACCodeSigningCert2)) {
        Write-Host "Which certificate do you want to use $PartialPrompt ?"
        Write-Host "[1] (WDAC Code Signing Cert 1)"
        Write-Host (Get-ChildItem $WDACCodeSigningCert | Select-Object Thumbprint,Subject)
        Write-Host "[2] (WDAC Code Signing Cert 2)"
        Write-Host (Get-ChildItem $WDACCodeSigningCert2 | Select-Object Thumbprint,Subject)
        $InputString = Read-Host -Prompt "Option Selection"
        while (($InputString -ne 1) -and ($InputString -ne 2)) {
            $InputString = Read-Host "Please select either `"1`" or `"2`""
        }
        if ($InputString -eq 1) {
            $result = $WDACCodeSigningCert
        } else {
            $result = $WDACCodeSigningCert2
        }
        return $result
    } elseif (Test-Path $WDACCodeSigningCert) {
        return $WDACCodeSigningCert
    } elseif (Test-Path $WDACCodeSigningCert2) {
        return $WDACCodeSigningCert2
    } else {
        return $null
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
            } elseif (-not (Test-Path $PSCodeSigningCert)) {
                throw "Cannot find the PowerShell code signing certificate in the certificate store. (Have you provided a full, valid cert:\ path?)"
            }
            $cert = Get-ChildItem -Path $PSCodeSigningCert
            Export-Certificate -Cert $cert -FilePath (Join-Path -Path $Destination -ChildPath "PSCodeSigning.cer")
            
        } catch {
            throw $_
        }
    }

    if ($WDACCodeSigner) {
        try {
            $WDACCodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
            $WDACCodeSigningCert2 = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate2"

            $WDACCodeSigningCert = [string](Select-WDACCertificateToUse -WDACCodeSigningCert $WDACCodeSigningCert -WDACCodeSigningCert2 $WDACCodeSigningCert2 -PartialPrompt "to add this signer rule (or rules)")

            if ((-not $WDACCodeSigningCert) -or ("" -eq $WDACCodeSigningCert)) {
                throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
            } elseif (-not ($WDACCodeSigningCert.ToLower() -match "cert\:\\")) {
                throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            } elseif (-not (Test-Path $WDACCodeSigningCert)) {
                throw "Cannot find the WDAC Signing certificate in the certificate store. (Have you provided a full, valid cert:\ path?)"
            }
            $cert = Get-ChildItem -Path $WDACCodeSigningCert
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
        if ($DestinationDirectory[-1] -eq "\") {
            #You will get an error if the trailing backslash isn't cut off
            $DestinationDirectory = $DestinationDirectory.Substring(0,$DestinationDirectory.Length-1)
        }

        $WDACCodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
        $WDACCodeSigningCert2 = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate2"
        $WDACCodeSigningCert = [string](Select-WDACCertificateToUse -WDACCodeSigningCert $WDACCodeSigningCert -WDACCodeSigningCert2 $WDACCodeSigningCert2 -PartialPrompt "to sign this WDAC policy")

        if ((-not $WDACCodeSigningCert) -or ("" -eq $WDACCodeSigningCert)) {
            throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
        } elseif (-not ($WDACCodeSigningCert.ToLower() -match "cert\:\\")) {
            throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
        }
        
        $cert = Get-ChildItem -Path $WDACCodeSigningCert -ErrorAction Stop
        $thumbprint = $cert.Thumbprint
        
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

        Start-Process $SignTool -ArgumentList 'sign', '/v' , '/n', "`"$cert_subject`"", '/fd', 'sha256', '/p7co', '1.3.6.1.4.1.311.79.1', '/p7', "`"$DestinationDirectory`"", '/sha1', $thumbprint, "`"$CIPPolicyPath`"" -Wait -NoNewWindow -ErrorAction Stop | Out-Null
        
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


