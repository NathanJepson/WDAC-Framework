if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

function Compare-Versions {
#Source: https://www.geeksforgeeks.org/compare-two-version-numbers/
    Param(
        $Version1,
        $Version2
    )
    $vnum1,$vnum2 = 0;

    for ($i=$j=0; $i -lt $Version1.Length -or $j -lt $Version2.Length;) {
        while ($i -lt ($version1.Length) -and ($Version1[$i] -ne ".")) {
            $vnum1 = ($vnum1 * 10) + [int]($Version1[$i]);
            $i++;
        }
        while ($j -lt ($Version2.Length) -and ($Version2[$j] -ne ".")) {
            $vnum2 = ($vnum2 * 10) + [int]($Version2[$j]);
            $j++;
        }

        if ($vnum1 -gt $vnum2) {
            return 1; #Version1 is bigger
        } 
        if ($vnum2 -gt $vnum1) {
            return -1; #Version2 is bigger
        }
        $vnum1,$vnum2 = 0; 
        $i++;
        $j++
    }
    return 0; #They are the same version number
}

function Get-XMLFromMDFileParser {
    [CmdletBinding()]
    param (
        [string[]]$lines
    )

    $result = @()
    $startXML = $false
    foreach ($line in $lines) {
        if ($line -match "``````xml") {
            $startXML = $true
        } elseif ($line -match "``````") {
            $startXML = $false
            return $result
        } elseif ($startXML) {
            $result += $line
        }
    }

    return $null
}

function Get-DriverBlockRules {
    [CmdletBinding()]
    param (
        [bool]$DoNotCacheRecommended
    )

    try {
        
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md"))) {
            Write-Verbose "Retrieving driver block rules from Github.com."
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md") -ErrorAction Stop 
        }
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml"))) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/WDAC-Toolkit/main/WDAC-Policy-Wizard/app/MSIX/Recommended_Driver_Blocklist.xml" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml") -ErrorAction Stop
        }
    } catch {
        throw "Trouble retrieving recommended driver block rules from github.com"
    }

    $linesMDFile = Get-Content (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md")
    $XMLResult = Get-XMLFromMDFileParser -lines $linesMDFile
    if ($XMLResult) {
        Set-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.xml") -Value $XMLResult -Force

        [xml]$XML_ITProDocs = Get-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.xml")
        [xml]$XML_WDACWizard = Get-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml")
        $ITProDocsVersion = $XML_ITProDocs.SiPolicy.VersionEx
        $WizardVersion = $XML_WDACWizard.SiPolicy.VersionEx
        
        if ( (Compare-Versions -Version1 $ITProDocsVersion -Version2 $WizardVersion) -eq 1) {
            $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.xml")
        } else {
            $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml")
        }
    } else {
        $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml")
    }
    
    if ($DoNotCacheRecommended) {
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.xml") -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md") -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml") -Force -ErrorAction SilentlyContinue
    }

    return $rules
}

function Get-UserModeBlockRules {
    [CmdletBinding()]
    param (
        [bool]$DoNotCacheRecommended
    )

    try {
        
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md"))) {
            Write-Verbose "Retrieving user mode block rules from Github.com."
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md") -ErrorAction Stop 
        }
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml"))) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/WDAC-Toolkit/main/WDAC-Policy-Wizard/app/MSIX/Recommended_UserMode_Blocklist.xml" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml") -ErrorAction Stop
        }
    } catch {
        throw "Trouble retrieving recommended user mode block rules from github.com"
    }

    $linesMDFile = Get-Content (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md")
    $XMLResult = Get-XMLFromMDFileParser -lines $linesMDFile
    if ($XMLResult) {
        Set-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.xml") -Value $XMLResult -Force

        [xml]$XML_ITProDocs = Get-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.xml")
        [xml]$XML_WDACWizard = Get-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml")
        $ITProDocsVersion = $XML_ITProDocs.SiPolicy.VersionEx
        $WizardVersion = $XML_WDACWizard.SiPolicy.VersionEx
        
        if ( (Compare-Versions -Version1 $ITProDocsVersion -Version2 $WizardVersion) -eq 1) {
            $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.xml")
        } else {
            $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml")
        }
    } else {
        $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml")
    }
    
    if ($DoNotCacheRecommended) {
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.xml") -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md") -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml") -Force -ErrorAction SilentlyContinue
    }

    return $rules
}

function Get-AllowMicrosoftModeRules {
    [CmdletBinding()]
    param (
        [bool]$DoNotCacheRecommended
    )

    try {
        
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml"))) {
            Write-Verbose "Retrieving AllowMicrosoft.xml policy from Github.com."
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/WDAC-Toolkit/main/WDAC-Policy-Wizard/app/MSIX/AllowMicrosoft.xml" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml") -ErrorAction Stop 
        }
    } catch {
        throw "Trouble retrieving AllowMicrosoft.xml policy from Github.com."
    }

    if (Test-Path "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml") {
        [XML]$ExampleAllowMicrosoft = Get-Content -Path "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
        $ExampleAllowMicrosoftVersion = $ExampleAllowMicrosoft.SiPolicy.VersionEx
    }

    if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml")) {
        [XML]$WizardAllowMicrosoft = Get-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml")
        $WizardAllowMicrosoftVersion = $WizardAllowMicrosoft.SiPolicy.VersionEx
    }

    if ($ExampleAllowMicrosoftVersion -and $WizardAllowMicrosoftVersion) {
        if ((Compare-Versions -Version1 $ExampleAllowMicrosoftVersion -Version2 $WizardAllowMicrosoftVersion) -eq 1) {
            $rules = Get-CIPolicy -FilePath "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
        } else {
            $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml")
        }
    } elseif ($ExampleAllowMicrosoft) {
        $rules = Get-CIPolicy -FilePath "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
    } else {
        $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml")
    }

    if ($DoNotCacheRecommended) {
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\allow-microsoft-wizard.xml") -Force -ErrorAction SilentlyContinue
    }

    return $rules
}

function Get-WindowsModeRules {
    [CmdletBinding()]
    param (
        [bool]$DoNotCacheRecommended
    )

    try {
        
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml"))) {
            Write-Verbose "Retrieving DefaultWindows.xml policy from Github.com."
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/WDAC-Toolkit/main/WDAC-Policy-Wizard/app/MSIX/DefaultWindows_Audit.xml" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml") -ErrorAction Stop 
        }
    } catch {
        throw "Trouble retrieving DefaultWindows.xml policy from Github.com."
    }

    
    if (Test-Path "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml") {
        [XML]$ExampleWindowsMode = Get-Content -Path "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
        $ExampleWindowsModeVersion = $ExampleWindowsMode.SiPolicy.VersionEx
    }

    if (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml")) {
        [XML]$WizardWindowsMode = Get-Content -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml")
        $WizardWindowsmodeVersion = $WizardWindowsMode.SiPolicy.VersionEx
    }

    if ($ExampleWindowsModeVersion -and $WizardWindowsmodeVersion) {
        if ((Compare-Versions -Version1 $ExampleWindowsModeVersion -Version2 $WizardWindowsmodeVersion) -eq 1) {
            $rules = Get-CIPolicy -FilePath "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
        } else {
            $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml")
        }
    } elseif ($ExampleWindowsModeVersion) {
        $rules = Get-CIPolicy -FilePath "$($Env:WINDIR)\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
    } else {
        $rules = Get-CIPolicy -FilePath (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml")
    }

    if ($DoNotCacheRecommended) {
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\windows-mode-wizard.xml") -Force -ErrorAction SilentlyContinue
    }

    return $rules
}

Export-ModuleMember -Function Get-DriverBlockRules, Get-UserModeBlockRules, Get-AllowMicrosoftModeRules, Get-WindowsModeRules