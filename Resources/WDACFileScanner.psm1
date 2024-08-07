$SigningScenarios = @{}
filter Get-TBSHash {
    <#
        .SYNOPSIS
        Get the TBS hash from a X509Certificate2 object    

        .DESCRIPTION
        Credit: Matthew Graber 
        Source: https://gist.github.com/mattifestation/660d7e17e43e8f32c38d820115274d2e

        .EXAMPLE
        ls 'C:\Windows\System32\*' -Include '*.dll' | Get-AuthenticodeSignature | Select -ExpandProperty SignerCertificate | Get-TBSHash

        .EXAMPLE
        $Drivers = Get-SystemDriver -ScanPath "C:\Program Files\Google\" -NoScript -NoShadowCopy -UserPEs
        foreach ($Driver in $Drivers) {
            foreach ($Signer in $Driver.Signers) {
                $Signer.Signer.Certificates[-1] | Get-TBSHash   #This gives the LeafCert TBS hash
                $Signer.Signer.Certificates[0] | Get-TBSHash    #This gives the PcaCert TBS hash
            }
        }
    #>
    [OutputType([String])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;

    namespace Crypto {
        public struct CRYPT_DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        public struct CRYPT_OBJID_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public string pszObjId;
            public CRYPT_OBJID_BLOB Parameters;
        }

        public struct CRYPT_BIT_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
        }

        public struct CERT_SIGNED_CONTENT_INFO
        {
            public CRYPT_DATA_BLOB ToBeSigned;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPT_BIT_BLOB Signature;
        }

        public class NativeMethods {
            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptDecodeObject(uint dwCertEncodingType, IntPtr lpszStructType, [In] byte[] pbEncoded, uint cbEncoded, uint dwFlags, [Out] IntPtr pvStructInto, ref uint pcbStructInfo);
        }
    }
'@


    $HashOIDs = @{
        '1.2.840.113549.1.1.4' = 'MD5'
        '1.2.840.113549.1.1.5' = 'SHA1'
        '1.3.14.3.2.29' = 'SHA1'
        '1.2.840.113549.1.1.11' = 'SHA256'
        '1.2.840.113549.1.1.12' = 'SHA384'
        '1.2.840.113549.1.1.13' = 'SHA512'
    }

    $CertBytes = $Certificate.RawData

    $X509_PKCS7_ENCODING = 65537
    $X509_CERT = 1
    $CRYPT_DECODE_TO_BE_SIGNED_FLAG = 2
    $ErrorMoreData = 234

    $TBSData = [IntPtr]::Zero
    [UInt32] $TBSDataSize = 0

    $Success = [Crypto.NativeMethods]::CryptDecodeObject(
        $X509_PKCS7_ENCODING,
        [IntPtr] $X509_CERT,
        $CertBytes,
        $CertBytes.Length,
        $CRYPT_DECODE_TO_BE_SIGNED_FLAG,
        $TBSData,
        [ref] $TBSDataSize
    ); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if((-not $Success) -and ($LastError -ne $ErrorMoreData)) 
    {
        throw "[CryptDecodeObject] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    $TBSData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TBSDataSize)

    $Success = [Crypto.NativeMethods]::CryptDecodeObject(
        $X509_PKCS7_ENCODING,
        [IntPtr] $X509_CERT,
        $CertBytes,
        $CertBytes.Length,
        $CRYPT_DECODE_TO_BE_SIGNED_FLAG,
        $TBSData,
        [ref] $TBSDataSize
    ); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if((-not $Success)) 
    {
        throw "[CryptDecodeObject] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    $SignedContentInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TBSData, [Type][Crypto.CERT_SIGNED_CONTENT_INFO])

    $TBSBytes = New-Object Byte[]($SignedContentInfo.ToBeSigned.cbData)
    [Runtime.InteropServices.Marshal]::Copy($SignedContentInfo.ToBeSigned.pbData, $TBSBytes, 0, $TBSBytes.Length)

    [Runtime.InteropServices.Marshal]::FreeHGlobal($TBSData)

    $HashAlgorithmStr = $HashOIDs[$SignedContentInfo.SignatureAlgorithm.pszObjId]

    if (-not $HashAlgorithmStr) { throw 'Hash algorithm is not supported or it could not be retrieved.' }

    $HashAlgorithm = [Security.Cryptography.HashAlgorithm]::Create($HashAlgorithmStr)

    $TBSHashBytes = $HashAlgorithm.ComputeHash($TBSBytes)

    ($TBSHashBytes | ForEach-Object { $_.ToString('X2') }) -join ''
}


function Get-SystemDriversModified {
    [CmdletBinding()]
    param (
        [switch]$Audit,
        [switch]$NoScript,
        [switch]$NoShadowCopy,
        [string[]]$OmitPaths,
        [string]$PathToCatroot,
        [string]$ScanPath,
        [switch]$ScriptFileNames,
        [switch]$UserPEs
    )

    try {
        $DateTime = Get-Date -Format "MM/dd/yyyy h:mm:ss tt"
        $Drivers = Get-SystemDriver -Audit:$Audit -NoScript:$NoScript -NoShadowCopy:$NoShadowCopy -OmitPaths $OmitPaths -PathToCatroot $PathToCatroot -ScanPath $ScanPath -ScriptFileNames:$ScriptFileNames -UserPEs:$UserPEs -ErrorAction Stop

        $DriversMSI = $Drivers | Where-Object {$_.isPE -eq $false}
        $DriversPE = $Drivers | Where-Object {$_.isPE -eq $true}
    
        if ((($DriversMSI.Count + $DriversPE.Count) -ne $Drivers.Count)) {
            throw "Not able to subdivide drivers between PE and MSIorScript correctly."
        }
    
        $ProcessID = $PID
        $User = whoami.exe
        $Hostname = HOSTNAME.EXE
        $ProcessName = "System file scan"

        $MSIs = @()
        $PEs = @()
    
        foreach ($Driver in $DriversMSI) {
            $Signers = $null
            if ($Driver.Signers.Count -ge 1) {
                $Signers = @()
                $SignerIndex = 0
                foreach ($Signer in $Driver.Signers) {

                    $Publisher = $Signer.Chain.ChainElements[0].Certificate

                    #According to how the ConfigCI module works, the PCACert is often just 1 level below the root certificate, even for 4 certificates
                    # (unless the only other cert is a root certificate)
                    if ($Signer.Chain.ChainElements.Count -eq 2) {
                        $Issuer = $Signer.Chain.ChainElements[1].Certificate
                    } elseif ($Signer.Chain.ChainElements.Count -ne 1) {
                        # -2 will get the certificate below root
                        $Issuer = $Signer.Chain.ChainElements[$Signer.Chain.ChainElements.Count -2].Certificate
                    }

                    $PublisherTBSHash = $Publisher | Get-TBSHash
                    $NotValidBefore = $Publisher.NotBefore
                    $NotValidAfter = $Publisher.NotAfter

                    $Publisher.Subject -match '(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))' | Out-Null
                    $PublisherName = $Matches[0]
                    
                    if ($Issuer) {
                        $IssuerTBSHash = $Issuer | Get-TBSHash
                        $Issuer.Subject -match '(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))' | Out-Null
                        $IssuerName = $Matches[0]
                    }

                    $Signers += New-Object -TypeName PSObject -Property ([Ordered]@{
                        SignatureIndex = $SignerIndex
                        # Hash = $null
                        # PageHash = $SignerData.PageHash
                        # SignatureType = $null
                        # ValidatedSigningLevel = $null
                        # VerificationError = $null
                        # Flags = $null
                        # PolicyBits = $null
                        NotValidBefore = $NotValidBefore
                        NotValidAfter = $NotValidAfter
                        PublisherName = $PublisherName
                        IssuerName = $IssuerName
                        PublisherTBSHash = $PublisherTBSHash
                        IssuerTBSHash = $IssuerTBSHash
                    })
    
                    $SignerIndex += 1
                }
            }

            $SigningScenario = $null
            if ($Driver.UserMode -eq $true) {
                $SigningScenario = "UserMode"
            } else {
                $SigningScenario = "Driver"
            }

            $Signed = $false
            if ($Signers.Count -ge 1) {
                $Signed = $true
            }

            $SignerInfo = $null
            if ($Signers.Count -ge 1) {
                $SignerInfo = ($Signers | Sort-Object -Property SignatureIndex)
            }

            $MSIs += New-Object -TypeName PSObject -Property ([Ordered] @{
                PSComputerName = $Hostname
                TimeCreated = $DateTime
                ProcessID = $ProcessID
                User = $User
                #EventType = $null
                FilePath = $Driver.FriendlyName
                SHA1FileHash = $Driver.Hash
                SHA256FileHash = $Driver.Hash256
                SIPHash256 = $Driver.SIPHash256
                #SHA256AuthenticodeHash = 
                UserWriteable = $Driver.UserWriteable
                Signed = $Signed
                SignerInfo = $SignerInfo
            })
        }
    
        foreach ($Driver in $DriversPE) {
            $Signers = $null
            try {
                $FlatHash = (Get-FileHash $Driver.FilePath -ErrorAction Stop).Hash
            } catch {
                Write-Warning "The following file path was either not resolved properly or was not present on disk: $($Driver.FilePath)"
                continue
            }

            if ($Driver.Signers.Count -ge 1) {
                $Signers = @()
                $SignerIndex = 0
                foreach ($Signer in $Driver.Signers) {

                    $Publisher = $Signer.Chain.ChainElements[0].Certificate

                    #According to how the ConfigCI module works, the PCACert is often just 1 level below the root certificate, even for 4 certificates
                    # (unless the only other cert is a root certificate)
                    if ($Signer.Chain.ChainElements.Count -eq 2) {
                        $Issuer = $Signer.Chain.ChainElements[1].Certificate
                    } elseif ($Signer.Chain.ChainElements.Count -ne 1) {
                        # -2 will get the certificate below root
                        $Issuer = $Signer.Chain.ChainElements[$Signer.Chain.ChainElements.Count -2].Certificate
                    }

                    $PublisherTBSHash = $Publisher | Get-TBSHash
                    $NotValidBefore = $Publisher.NotBefore
                    $NotValidAfter = $Publisher.NotAfter

                    $Publisher.Subject -match '(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))' | Out-Null
                    $PublisherName = $Matches[0]

                    if ($Issuer) {
                        $IssuerTBSHash = $Issuer | Get-TBSHash
                        $Issuer.Subject -match '(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))' | Out-Null
                        $IssuerName = $Matches[0]
                    }

                    $Signers += New-Object -TypeName PSObject -Property ([Ordered]@{
                        SignatureIndex = $SignerIndex
                        # Hash = $null
                        # PageHash = $null
                        # SignatureType = $null
                        # ValidatedSigningLevel = $null
                        # VerificationError = $null
                        # Flags = $null
                        # PolicyBits = $null
                        NotValidBefore = $NotValidBefore
                        NotValidAfter = $NotValidAfter
                        PublisherName = $PublisherName
                        IssuerName = $IssuerName
                        PublisherTBSHash = $PublisherTBSHash
                        IssuerTBSHash = $IssuerTBSHash
                    })
    
                    $SignerIndex += 1
                }
            }

            $SigningScenario = $null
            if ($Driver.UserMode -eq $true) {
                $SigningScenario = "UserMode"
            } else {
                $SigningScenario = "Driver"
            }

            $SignerInfo = $null
            if ($Signers.Count -ge 1) {
                $SignerInfo = ($Signers | Sort-Object -Property SignatureIndex)
            }

            if ($null -ne $SigningScenarios[$Driver.FilePath]) {
            # If there is a 2nd identical instance of an app entry -- with just the signing scenario different -- then modify the previous app entry to 
            # indicate that it's a binary that lives in kernel mode and usermode land
                if ($SigningScenarios[$Driver.FilePath] -ne $SigningScenario) {
                    if ((($SigningScenarios[$Driver.FilePath] -eq "UserMode") -and ($SigningScenario -eq "Driver")) -or (($SigningScenarios[$Driver.FilePath] -eq "Driver") -and ($SigningScenario -eq "UserMode"))) {
                        ($PEs | Where-Object {$_.UnresolvedFilePath -eq $Driver.FilePath}).SigningScenario = "DriverAndUserMode"
                        $SigningScenarios[$Driver.FilePath] = "DriverAndUserMode"
                        continue
                    }
                }
            } else {
                $SigningScenarios += @{ ($Driver.FilePath) = $SigningScenario}
            }

            $PEs += New-Object -TypeName PSObject -Property ([Ordered] @{
                PSComputerName = $Hostname
                TimeCreated = $DateTime
                ProcessID = $ProcessID
                User = $User
                #EventType = $null
                SigningScenario = $SigningScenario
                UnresolvedFilePath = $Driver.FilePath
                FilePath = $Driver.FriendlyName
                #SHA1FileHash = $null
                SHA1AuthenticodeHash = $Driver.Hash
                SHA256FileHash = $FlatHash
                SHA256AuthenticodeHash = $Driver.Hash256
                SIPHash256 = $Driver.SIPHash256
                PageHash = $Driver.PageHash
                PageHash256 = $Driver.PageHash256
                # RequestedSigningLevel = $null
                # UnresolvedProcessName = $ProcessName
                ProcessName = $ProcessName
                # ValidatedSigningLevel = $null
                # PolicyName = $null
                # PolicyID = $null
                # PolicyGUID = $null
                # PolicyHash = $null
                OriginalFileName = $Driver.FileName
                InternalName = $Driver.InternalName
                FileDescription = $Driver.FileDescription
                ProductName = $Driver.ProductName
                FileVersion = $Driver.FileVersion
                PackageFamilyName = $Driver.PackageFamilyName
                UserWriteable = $Driver.UserWriteable
                #FailedWHQL = $null
                SignerInfo = $SignerInfo
            })
        }

        return $PEs,$MSIs

    } catch {
        throw $_
    }
}

Export-ModuleMember -Function Get-SystemDriversModified