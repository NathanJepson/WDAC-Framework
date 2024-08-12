function Test-ValidWDACSignedPolicySignature {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $CISignedPolicyFile,
        [switch]$Thorough
    )

    try {
        Add-Type -AssemblyName 'System.Security'
        $SignedCryptoMsgSyntax = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms
        $SignedCryptoMsgSyntax.Decode([System.IO.File]::ReadAllBytes($CISignedPolicyFile))

        if ($Thorough) {
            #This line of code below checks the digital signature is valid AS WELL AS the signers' certificates 
            #...are validated, and the purposes of the certificates are validated. The function
            #...returns with no output if it is vaild, otherwise it will throw an exception.
            $SignedCryptoMsgSyntax.CheckSignature($false)
        } else {
            #This line of code below checks only the digital signature
            #...and returns no output if it is valid, otherwise it will throw an exception
            $SignedCryptoMsgSyntax.CheckSignature($true)
        }
        
        return $true
    } catch {
        throw $_
    }
}

Export-ModuleMember -Function Test-ValidWDACSignedPolicySignature