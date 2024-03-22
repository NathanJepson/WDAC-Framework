if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    Write-Verbose "The current file is in the SignedModules folder."
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")) {
    Import-Module (Join-Path -Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")
} else {
    Import-Module (Join-Path -Path $PSModuleRoot -ChildPath "Resources\JSON-LocalStorageTools.psm1")
}

function Get-YesOrNoPrompt {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt
    )

    Write-Host ($Prompt + " (Y/N): ") -NoNewline
    while ($true) {
        $InputString = Read-Host
        if ($InputString.ToLower() -eq "y") {
            return $true
        } elseif ($InputString.ToLower() -eq "n") {
            return $false
        } else {
            Write-Host "Not a valid option. Please supply y or n."
        }
    }
}

function Get-FullValidFilePath {
    [CmdletBinding()]
    Param (
        $Prompt,
        $NeededFileExtension
    )

    $UserInput = Read-Host -Prompt $Prompt
    $Valid = $false

    while (-not ($Valid)) {
        if (-not $UserInput) {
            $UserInput = Read-Host -Prompt "Not a valid input. Insert a full valid file path"
        } else {
            if (-not (Test-Path $UserInput)) {
                $UserInput = Read-Host -Prompt "Not a valid file path. Please input a valid file path"
            } else {
                if ($NeededFileExtension) {
                    if ((Split-Path $UserInput -Extension).ToLower() -ne $NeededFileExtension.ToLower()) {
                        $UserInput = Read-Host -Prompt "Designated file is not a $NeededFileExtension file."
                        continue
                    }
                }
                $Valid = $true
            }
        }
    }

    return $UserInput
}

function Get-FullValidCertPath {
    [CmdletBinding()]
    Param (
        $Prompt
    ) 

    $UserInput = Read-Host -Prompt $Prompt
    $Valid = $false

    while (-not $Valid) {
        if ($UserInput -match "cert\:\\") {
            try {
                Get-ChildItem -Path $UserInput -ErrorAction Stop | Out-Null
                $Valid = $true
            } catch {
                $UserInput = Read-Host -Prompt "Not a valid certificate path. Provide a valid certificate path, thumbprint, or name."
                continue
            }
        } else {
            #Thumbprint or Cert Common Name
            $NoConditionMet = $true
            foreach ($cert in Get-ChildItem 'Cert:\CurrentUser\My') {
                if ($cert.Thumbprint.ToLower() -eq $UserInput.ToLower()) {
                    $UserInput = "Cert:\\CurrentUser\My\$($cert.Thumbprint)"
                    $NoConditionMet = $false
                    break
                } elseif ($cert.Subject -match "(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))") {
                    $cert_subject = $Matches[0]
                    if ($cert_subject.ToLower() -eq $UserInput.ToLower()) {
                        $UserInput = "Cert:\\CurrentUser\My\$($cert.Thumbprint)"
                        $NoConditionMet = $false
                        break
                    }
                } else {
                    continue
                }
            }

            #Do one last check through the first if statement
            if (-not $NoConditionMet) {
                continue
            }
        }

        if (-not $Valid) {
            $UserInput = Read-Host "Not a valid Common Name or thumbprint. Insert a valid certificate or fully qualified certificate path."
        }
    }

    return $UserInput
}


$SqliteAssembly = (Get-LocalStorageJSON -ErrorAction Stop)."SqliteAssembly"
$GetSqliteAssembly = $false
if (-not $SqliteAssembly -or ($SqliteAssembly -eq "Full_Path_To_Sqlite_DLL")) {
    $GetSqliteAssembly = $true
} elseif (-not (Test-Path $SqliteAssembly)) {
    $GetSqliteAssembly = $true
}

if ($GetSqliteAssembly) {
    Write-Host "You must download the Sqlite .dll binary associated with .NET Core (i.e., compatible with PowerShell 7)."
    Write-Host "This binary is usually on the main SQlite website at this URL: https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki"
    Write-Host "For a 64-bit machine, the name of the download is `"sqlite-netFx46-binary-x64-2015-1.0.118.0.zip`". When unzipped, it should contain a file called System.Data.SQLite.dll."
    Write-Host "This project has only been tested with this specific binary, on a 64-bit Windows 10 machine running PowerShell 7."
    Write-Host "Make sure that System.Data.SQLite.dll remains in the same directory as all other dependencies from the .ZIP file."
    $SqliteAssembly = Get-FullValidFilePath -Prompt "Once you've downloaded the file, but the full filepath of the binary here`n" -NeededFileExtension ".dll"
    try {
        Set-ValueLocalStorageJSON -Key "SqliteAssembly" -Value $SqliteAssembly -ErrorAction Stop
    } catch {
        throw "Unable to update cached Sqlite binary."
    }
}

$DatabaseLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingDatabase"."Location"
#TODO: Handle other database location types
if ((-not $DatabaseLocation) -or (-not (Test-Path $DatabaseLocation))) {
    Write-Host "Provide information regarding your new Sqlite trust database."
    $DBName = $null
    $DBLocation = $null
    try {
        $DBName = Read-Host -Prompt "What should the name of your database be?"
        while ((Split-Path $DBName -Extension) -ne ".db") {
            $DBName += ".db"
        }
        
        $DBLocation = Read-Host -Prompt "Where should your Sqlite trust database be placed? (A directory)"
        while (-not (Test-Path $DBLocation)) {
            $DBLocation = Read-Host -Prompt "Please provide a valid location for your database"
        }

        if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath "SignedModules\New-WDACTrustDB.psm1")) {
            $NewDBModule = (Join-Path -Path $PSModuleRoot -ChildPath "SignedModules\New-WDACTrustDB.psm1")
        } else {
            $NewDBModule = (Join-Path -Path $PSModuleRoot -ChildPath "New-WDACTrustDB.psm1")
        }

        Import-Module $NewDBModule -ErrorAction Stop

        New-WDACTrustDB -DBName $DBName -Destination $DBLocation -SqliteAssembly $SqliteAssembly -ErrorAction Stop

    } catch {
        Write-Error $_
        throw "Error in creating new trust database."
    }

    try {
        Set-ValueLocalStorageJSON -Key "WorkingDatabase" -Subkey "Location" -Value (Join-Path $DBLocation -ChildPath $DBName) -ErrorAction Stop
        Set-ValueLocalStorageJSON -Key "WorkingDatabase" -Subkey "IsParent" -Value $true -ErrorAction Stop
        #TODO: Handle other location types other than LOCAL
    } catch {
        Write-Verbose $_
        throw "Unable to set database location in LocalStorage.json."
    }
}

$WDACPoliciesDirectory  = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
$RemoteStagingDirectory = (Get-LocalStorageJSON -ErrorAction Stop)."RemoteStagingDirectory"

if (-not ($WDACPoliciesDirectory)) {
    #TODO: Handle other location types
    $WDACPoliciesDirectory = Get-FullValidFilePath -Prompt "Enter a local file directory where WDAC policies will be stored"
    try {
        Set-ValueLocalStorageJSON -Key "WorkingPoliciesDirectory" -Subkey "Location" -Value $WDACPoliciesDirectory -ErrorAction Stop
        Set-ValueLocalStorageJSON -Key "WorkingPoliciesDirectory" -Subkey "Type" -Value "Local" -ErrorAction Stop
    } catch {
        throw "Unable to update WDAC policies directory location LocalStorage.json."
    }
}

if (-not ($RemoteStagingDirectory)) {
    $RemoteStagingDirectory = Read-Host "Enter remote staging directory where WDAC policies will be temporarily stored (and purged) on remote devices."
    while ($true) {
        try {
            Split-Path $RemoteStagingDirectory -Qualifier -ErrorAction Stop | Out-Null
            break
        } catch {
            Write-Warning "The RemoteStagingDirectory must have a qualifier such as `"C:\`" or `"D:\`" at the beginning."
            $RemoteStagingDirectory = Read-Host "Enter valid remote staging directory"
        }
    }
    try {
        Set-ValueLocalStorageJSON -Key "RemoteStagingDirectory" -Value $RemoteStagingDirectory -ErrorAction Stop
    } catch {
        throw "Unable to update remote staging directory location LocalStorage.json."
    }
}

$RefreshToolx86 = (Get-LocalStorageJSON -ErrorAction Stop)."RefreshTool_x86"
$RefreshToolAMD64 = (Get-LocalStorageJSON -ErrorAction Stop)."RefreshTool_AMD64"
$RefreshToolARM64 = (Get-LocalStorageJSON -ErrorAction Stop)."RefreshTool_ARM64"

if ((-not $RefreshToolx86) -and (-not $RefreshToolAMD64) -and (-not $RefreshToolARM64)) {
    
    Write-Host "We recommend downloading the Refresh WDAC policy tool for your environment. (There is a different one for CPU architectures of X86 (32-bit), AMD64, and ARM64)."
    Write-Host "They can be downloaded from here: https://www.microsoft.com/en-us/download/details.aspx?id=102925"

    if (Get-YesOrNoPrompt -Prompt "Once those are downloaded, you can input the full filepaths of the executables. `nContinue with adding refresh tools?") {
        while (-not ($RefreshToolx86 -and $RefreshToolAMD64 -and $RefreshToolARM64)) {
            
            $CPU = Read-Host -Prompt "Which Refresh tool are you adding? (X86, AMD64, ARM64)"

            if ($CPU.ToLower() -eq "x86") {
                $RefreshToolx86 = Get-FullValidFilePath -Prompt "Enter Full Filepath for RefreshPolicy(X86).exe" -NeededFileExtension ".exe"
                if (Get-YesOrNoPrompt -Prompt "Are you done adding refresh tools?") {
                    break
                }
            } elseif ($CPU.ToLower() -eq "AMD64") {
                $RefreshToolAMD64 = Get-FullValidFilePath -Prompt "Enter Full Filepath for RefreshPolicy(AMD64).exe" -NeededFileExtension ".exe"
                if (Get-YesOrNoPrompt -Prompt "Are you done adding refresh tools?") {
                    break
                }
            } elseif ($CPU.ToLower() -eq "ARM64") {
                $RefreshToolARM64 = Get-FullValidFilePath -Prompt "Enter Full Filepath for RefreshPolicy(ARM64).exe" -NeededFileExtension ".exe"
                if (Get-YesOrNoPrompt -Prompt "Are you done adding refresh tools?") {
                    break
                }
            } else {
                Write-Host "Not a valid CPU architecture."
            }
        }


        if ($RefreshToolx86) {
            try {
                Set-ValueLocalStorageJSON -Key "RefreshTool_x86" -Value $RefreshToolx86 -ErrorAction Stop
            } catch {
                throw "Unable to update a Refresh tool location in LocalStorage.json."
            }
        }
        if ($RefreshToolAMD64) {
            try {
                Set-ValueLocalStorageJSON -Key "RefreshTool_AMD64" -Value $RefreshToolAMD64 -ErrorAction Stop
            } catch {
                throw "Unable to update a Refresh tool location in LocalStorage.json."
            }
        }
        if ($RefreshToolARM64) {
            try {
                Set-ValueLocalStorageJSON -Key "RefreshTool_ARM64" -Value $RefreshToolARM64 -ErrorAction Stop
            } catch {
                throw "Unable to update a Refresh tool location in LocalStorage.json."
            }
        }
    }
}

$PSCodeSigningJSON = (Get-LocalStorageJSON -ErrorAction Stop)."PowerShellCodeSigningCertificate"

if (-not ($PSCodeSigningJSON.ToLower() -match "cert\:\\")) {
    if (Get-YesOrNoPrompt -Prompt "Do you have a PowerShell code signing certificate? (Alternatively, you can make one, and then select `"Y`" once you've done so.)") {
        $PSCodeSigningJSON = Get-FullValidCertPath -Prompt "What is the fully qualified path or thumbprint or Common Name of this certificate? `n Example: Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3 `n Other Example: 005A924AA26ABD88F84D6795CCC0AB09A6CE88E3 `n Other Example: PSCodeSigningCert `nEnter Common Name or Thumbprint or Cert Store Path"
        try {
            Set-ValueLocalStorageJSON -Key "PowerShellCodeSigningCertificate" -Value $PSCodeSigningJSON -ErrorAction Stop
        } catch {
            throw "Unable to update PowerShell signing certificate in LocalStorage.json."
        }
    }
}

if (Get-YesOrNoPrompt -Prompt "Do you plan on signing your WDAC policies?") {
    $WDACodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
    $SignToolLocation = (Get-LocalStorageJSON -ErrorAction Stop)."SignTool"
    if (-not ($WDACodeSigningCert.ToLower() -match "cert\:\\")) {
        if (Get-YesOrNoPrompt -Prompt "Do you have a WDAC Policy signing certificate with which to sign policies? `n(Instructions for making a new one with an on-prem CA are here: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/create-code-signing-cert-for-wdac)`nSelect `"Y`" once you've done so.") {
            $WDACodeSigningCert = Get-FullValidCertPath -Prompt "What is the fully qualified path or thumbprint or Common Name of this certificate? `n Example: Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3 `n Other Example: 005A924AA26ABD88F84D6795CCC0AB09A6CE88E3 `n Other Example: WDACSigningCert `nEnter Common Name or Thumbprint or Cert Store Path"
            try {
                Set-ValueLocalStorageJSON -Key "WDACPolicySigningCertificate" -Value $WDACodeSigningCert -ErrorAction Stop
            } catch {
                throw "Unable to update WDAC policy signing certificate in LocalStorage.json."
            }
        }
    }

    if ((-not $SignToolLocation) -or ($SignToolLocation -eq "Full_Path_To_SignTool.exe") -or (-not (Test-Path $SignToolLocation))) {
        $SignTool = Get-FullValidFilePath -Prompt "Please provide the full filepath of Microsoft's SignTool on your machine" -NeededFileExtension ".exe"
        try {
            Set-ValueLocalStorageJSON -Key "SignTool" -Value $SignTool -ErrorAction Stop
        } catch {
            throw "Unable to update SignTool.exe location in LocalStorage.json."
        }
    }
}

Write-Host "Setup is complete. You may now import the WDAC-Framework module."