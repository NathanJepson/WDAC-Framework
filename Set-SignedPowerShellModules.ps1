function Set-SignedPowerShellModules {
    <#
    .SYNOPSIS
    Signs all of the relevant PowerShell modules you could need and puts them in the "Signed Modules folder."

    .DESCRIPTION
    Iterates over each Powershell file .ps1,.psm1,.psd1, as well as imported modules such as WDACTools and then signs them, checks for valid signature, then puts them in directory "SignedModules." 
    This is so they are allowed to run when WDAC policies are implemented (but you will need to make sure to add appropriate signer rules in the WDAC policies.)

    .PARAMETER FileName
    NOTE: Not recommended. It is recommended that you sign all scripts and modules at once by not providing this argument.
    FileName for just the Module you want signed (otherwise, all modules will be signed and copied, overwriting the contents of the SignedModules folder).
    If it is in a folder of the module (for example, the Resources folder), you will need to provide that too; e.g., Resources\JSON-LocalStorageTools.psm1
    The FileName provided must much an element of the $Modules or $Scripts list.

    .PARAMETER PSCodeSigningCert
    Provide the cert:\ path for the certificate in your Windows certificate store. (e.g., "Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3")

    .PARAMETER SignInPlace
    Sign the modules and scripts without copying them to the SignedModulesFolder

    .EXAMPLE
    Set-SignedPowerShellModules

    .EXAMPLE
    Set-SignedPowerShellModules -FileName Get-WDACEvents.ps1"

    .EXAMPLE
    Set-SignedPowerShellModules -PSCodeSigningCert "Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3" -SignInPlace

    .EXAMPLE
    Set-SignedPowerShellModules -FileName Resources\JSON-LocalStorageTools.psm1
    #>

    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [ValidateNotNullOrEmpty()]
        [string]$PSCodeSigningCert,
        [switch]$SignInPlace
    )

    if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    } else {
        $PSModuleRoot = $PSScriptRoot
    }

    if ($FileName) {
        if (-not (Test-Path (Join-Path $PSModuleRoot -ChildPath $FileName))) {
            throw "Not a valid filename that you can sign. Please provide script or module names within WDAC-Framework or WDACTools."
            return
        } 

        $Extension = (Get-ChildItem (Join-Path $PSModuleRoot -ChildPath $FileName) | Select-Object Extension).Extension
        if ($Extension -ne ".ps1" -and $Extension -ne ".psm1" -and $Extension -ne ".psd1") {
            throw "You can only sign .ps1, .psm1, and .psd1 files in this repository."
            return
        }
    }

    $SignedModules = Join-Path $PSModuleRoot -ChildPath "SignedModules\"

    if (-not ($PSCodeSigningCert.ToLower() -match "cert\:\\") -and $PSCodeSigningCert) {
        throw "Not a valid certificate path for the signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
        return
    }

    $PSCodeSigningJSON = (Get-LocalStorageJSON)."PowerShellCodeSigningCertificate"

    if ( (-not $PSCodeSigningCert) -and $PSCodeSigningJSON) {
        if (-not ($PSCodeSigningJSON.ToLower() -match "cert\:\\")) {
            throw "Local cache does not specify a valid certificate path for the signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            return
        }
    }

    if ( ($PSCodeSigningCert -ne $PSCodeSigningJSON -and $PSCodeSigningJSON -and $PSCodeSigningCert) -or (-not $PSCodeSigningJSON -and $PSCodeSigningCert)) {
        Write-Host "The signing certificate provided does not match the one previously saved OR there isn't one saved already. Overwrite existing value? (Y/N)"
        $UserInput = Read-Host
        if ($UserInput.ToLower() -eq "y") {
            try {
                Set-ValueLocalStorageJSON -Key "PowerShellCodeSigningCertificate" -Value $PSCodeSigningCert -ErrorAction Stop
            } catch {
                Write-Warning "Unable to update cached code signing certificate value. Continuing execution of the script."
            }
        } elseif (-not ($UserInput.ToLower() -eq "n")) {
            Write-Warning "Not a valid input. Continuing script execution with the certificate provided to the commandlet."
        } 
    } elseif (-not $PSCodeSigningJSON -and -not $PSCodeSigningCert) {
        Write-Verbose "Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
        throw "There is not a valid certificate provided from local cache or passed to this commandlet OR there is a problem reading local storage. Please specify or set a Code Signing certificate."
        return
    }

    if (-not $PSCodeSigningCert) {
        $PSCodeSigningCert = $PSCodeSigningJSON
    }

    #Case 1: Only the name of one module is provided
    if ($FileName) {
        try {

            if ($SignInPlace) {
                $IsValid = Set-AuthenticodeSignature (Join-Path $PSModuleRoot -ChildPath $FileName) -Certificate (Get-ChildItem $PSCodeSigningCert)
            } else {
                $Copied = Copy-Item (Join-Path $PSModuleRoot -ChildPath $FileName) -Destination $SignedModules -PassThru -Force -ErrorAction Stop 
                $IsValid = Set-AuthenticodeSignature $Copied.ResolvedTarget -Certificate (Get-ChildItem $PSCodeSigningCert)
            }
            
            if ($IsValid.Status -ne "Valid") {
                throw "Unable to verify that the resultant file has a valid signature. Please make sure that a valid certificate is used to sign the file."
            }
        } catch {
            throw $_
            return
        }

        return
    }

    #Case 2: Sign all scripts and modules
    try {
        $ModulesFiles = Get-ChildItem -Path $PSModuleRoot -Include "*.ps1","*.psd1","*.psm1" -Recurse -ErrorAction Stop
        $ResourceFiles = Get-ChildItem -Path (Join-Path $PSModuleRoot -ChildPath "Resources") -Include "*.ps1","*.psm1" -Recurse -ErrorAction Stop
    } catch {
        throw $_
        return
    }

    if (-not (Test-Path (Join-Path $SignedModules -ChildPath "Resources"))) {
        New-Item -ItemType Directory -Name "Resources" -Path $SignedModules | Out-Null
    }

    $FileSources = @($ModulesFiles,$ResourceFiles)
    foreach ($FileSource in $FileSources) {
        foreach ($Module in $FileSource) {
            try {
                if ($SignInPlace) {
                    $IsValid = Set-AuthenticodeSignature $Module -Certificate (Get-ChildItem $PSCodeSigningCert) -ErrorAction Stop
                } else {
                    if ($ResourceFiles -contains $Module) {
                        $Copied = Copy-Item $Module -Destination "$SignedModules\Resources" -PassThru -Force -ErrorAction Stop 
                    } else {
                        $Copied = Copy-Item $Module -Destination $SignedModules -PassThru -Force -ErrorAction Stop 
                    }
                    $IsValid = Set-AuthenticodeSignature $Copied.ResolvedTarget -Certificate (Get-ChildItem $PSCodeSigningCert) -ErrorAction Stop

                    if ($IsValid.Status -ne "Valid") {
                        throw "Unable to verify that the resultant file $($Module.Name) has a valid signature. Please make sure that a valid certificate is used to sign the file."
                    }
                }
            } catch {
                Write-Warning $_
            }
        }
    }
}
