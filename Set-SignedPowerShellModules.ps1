function Set-SignedPowerShellModules {
    <#
    .SYNOPSIS
    Signs all of the relevant PowerShell modules you could need and puts them in the "Signed Modules folder."

    .DESCRIPTION
    Iterates over each Powershell file .ps1,.psm1,.psd1, as well as imported modules such as WDACTools and then signs them, checks for valid signature, then puts them in directory "SignedModules." 
    This is so they are allowed to run when WDAC policies are implemented (but you will need to make sure to add appropriate signer rules in the WDAC policies.)
    Signed files by default are put in the "SignedModules" folder EXCEPT for WDAC-Framework.psm1 and WDAC-Framework.psd1.

    .PARAMETER FileName
    NOTE: Not recommended. It is recommended that you sign all scripts and modules at once by not providing this argument.
    FileName for just the Module you want signed (otherwise, all modules will be signed and copied, overwriting the contents of the SignedModules folder).
    If it is in a folder of the module (for example, the Resources folder), you will need to provide that too; e.g., Resources\JSON-LocalStorageTools.psm1
    The FileName provided must match an element of the $Modules or $Scripts list.

    .PARAMETER PSCodeSigningCert
    Provide the cert:\ path for the certificate in your Windows certificate store. (e.g., "Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3")

    .PARAMETER SignInPlace
    Sign the modules and scripts without copying them to the SignedModulesFolder.

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
        Write-Verbose "The current file is in the SignedModules folder."
    } else {
        $PSModuleRoot = $PSScriptRoot
    }

    if ($FileName) {
        if (-not (Test-Path (Join-Path $PSModuleRoot -ChildPath $FileName))) {
            throw "Not a valid filename that you can sign. Please provide script or module names within WDAC-Framework or WDACTools."
        } 

        $Extension = (Get-ChildItem (Join-Path $PSModuleRoot -ChildPath $FileName) | Select-Object Extension).Extension
        if ($Extension -ne ".ps1" -and $Extension -ne ".psm1" -and $Extension -ne ".psd1") {
            throw "You can only sign .ps1, .psm1, and .psd1 files in this repository."
        }
    }

    $SignedModules = Join-Path $PSModuleRoot -ChildPath "SignedModules\"

    if (-not ($PSCodeSigningCert.ToLower() -match "cert\:\\") -and $PSCodeSigningCert) {
        throw "Not a valid certificate path for the signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
    }

    $PSCodeSigningJSON = (Get-LocalStorageJSON)."PowerShellCodeSigningCertificate"

    if ( (-not $PSCodeSigningCert) -and $PSCodeSigningJSON) {
        if (-not ($PSCodeSigningJSON.ToLower() -match "cert\:\\")) {
            throw "Local cache does not specify a valid certificate path for the signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
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
    }

    if (-not $PSCodeSigningCert) {
        $PSCodeSigningCert = $PSCodeSigningJSON
    }
    
    if (-not (Test-Path (Join-Path $SignedModules -ChildPath "Resources"))) {
        New-Item -ItemType Directory -Name "Resources" -Path $SignedModules -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path (Join-Path $SignedModules -ChildPath "WDACAuditing"))) {
        New-Item -ItemType Directory -Name "WDACAuditing" -Path $SignedModules -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path (Join-Path $SignedModules -ChildPath "WDAC Commit Tools"))) {
        New-Item -ItemType Directory -Name "WDAC Commit Tools" -Path $SignedModules -ErrorAction SilentlyContinue | Out-Null
    }

    #Case 1: Only the name of one module is provided
    if ($FileName) {
        try {

            if ($SignInPlace -or $FileName -eq "WDAC-Framework.psm1" -or $FileName -eq "WDAC-Framework.psd1") {
                $IsValid = Set-AuthenticodeSignature (Join-Path $PSModuleRoot -ChildPath $FileName) -Certificate (Get-ChildItem $PSCodeSigningCert)
            } else {
                $Copied = Copy-Item (Join-Path $PSModuleRoot -ChildPath $FileName) -Destination (Join-Path $SignedModules -ChildPath (Split-Path $FileName)) -PassThru -Force -ErrorAction Stop 
                $IsValid = Set-AuthenticodeSignature $Copied.ResolvedTarget -Certificate (Get-ChildItem $PSCodeSigningCert)
            }
            
            if ($IsValid.Status -ne "Valid") {
                throw "Unable to verify that the resultant file has a valid signature. Please make sure that a valid certificate is used to sign the file."
            }
        } catch {
            throw $_
        }

        return
    }

    #Case 2: Sign all scripts and modules
    try {
        #Appending "\*" to the end of the path is the only way you can use Get-ChildItem without specifying the "Recurse" flag
        $ModulesFiles = Get-ChildItem -Path ($PSModuleRoot + "\*") -Include ('*.ps1', '*.psm1', '*.psd1') -ErrorAction Stop
        $ResourceFiles = Get-ChildItem -Path ($PSModuleRoot + "\Resources\*") -Include "*.ps1","*.psm1" -ErrorAction Stop
        $WDACAuditingFiles = Get-ChildItem -Path ($PSModuleRoot + "\WDACAuditing\*") -Include "*.ps1","*.psm1" -ErrorAction Stop
        $WDACCommitToolsFiles = Get-ChildItem -Path ($PSModuleRoot + "\WDAC Commit Tools\*") -Include "*.ps1","*.psm1" -ErrorAction Stop
    } catch {
        throw $_
    }

    $FileSources = @($ModulesFiles,$ResourceFiles,$WDACAuditingFiles)
    foreach ($FileSource in $FileSources) {
        foreach ($Module in $FileSource) {
            try {
                $IsValid = $null
                if ($SignInPlace -or $Module.Name -eq "WDAC-Framework.psm1" -or $Module.Name -eq "WDAC-Framework.psd1") {
                    $IsValid = Set-AuthenticodeSignature $Module -Certificate (Get-ChildItem $PSCodeSigningCert) -ErrorAction Stop
                } else {
                    if ($ResourceFiles -contains $Module) {
                        $Copied = Copy-Item $Module -Destination "$SignedModules\Resources" -PassThru -Force -ErrorAction Stop 
                    } elseif ($WDACAuditingFiles -contains $Module) {
                        $Copied = Copy-Item $Module -Destination "$SignedModules\WDACAuditing" -PassThru -Force -ErrorAction Stop 
                    } elseif ($WDACCommitToolsFiles -contains $Module) {
                        $Copied = Copy-Item $Module -Destination "$SignedModules\WDAC Commit Tools" -PassThru -Force -ErrorAction Stop 
                    }
                    else {
                        $Copied = Copy-Item $Module -Destination $SignedModules -PassThru -Force -ErrorAction Stop 
                    }
                    $IsValid = Set-AuthenticodeSignature $Copied.ResolvedTarget -Certificate (Get-ChildItem $PSCodeSigningCert) -ErrorAction Stop
                }

                if ($IsValid.Status -ne "Valid") {
                    throw "Unable to verify that the resultant file $($Module.Name) has a valid signature. Please make sure that a valid certificate is used to sign the file."
                }

            } catch {
                Write-Warning $_
            }
        }
    }
    
    Write-Host "File signing process has completed. Please reload / reimport the WDAC-Framework module."

}
