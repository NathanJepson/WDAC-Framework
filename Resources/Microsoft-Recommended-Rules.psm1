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
        [switch]$DoNotCacheRecommended
    )

    try {
        Write-Verbose "Retrieving driver block rules from Github.com if they aren't in .WDACFrameworkData"
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md"))) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md") -ErrorAction Stop 
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
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.xml") -Force
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-itprodocs.md") -Force
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\driv-block-wdacwizard.xml") -Force
    }

    return $rules
}

function Get-UserModeBlockRules {
    [CmdletBinding()]
    param (
        [switch]$DoNotCacheRecommended
    )

    try {
        Write-Verbose "Retrieving driver block rules from Github.com if they aren't in .WDACFrameworkData"
        if (-not (Test-Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md"))) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md" -OutFile (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md") -ErrorAction Stop 
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
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.xml") -Force
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-itprodocs.md") -Force
        Remove-Item -Path (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\usermode-block-wdacwizard.xml") -Force
    }

    return $rules
}

function Get-AllowMicrosoftModeRules {
    [CmdletBinding()]
    param (
        [switch]$CachePolicy
    )
}

function Get-WindowsModeRules {
    [CmdletBinding()]
    param (
        [switch]$CachePolicy
    )
}