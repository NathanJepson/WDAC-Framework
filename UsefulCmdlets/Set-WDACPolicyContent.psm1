$ThisIsASignedModule = $false
if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\WorkingPolicies-and-DB-IO.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part2.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part2.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools_Part2.psm1")
}

function Set-WDACPolicyContent {
<#
    .SYNOPSIS
    This policy copies all FileRules, Signers, CiSigners, SupplementalSigners, UpdateSigners, and EKUs from a source policy
    to a destination policy (overwriting those sections in the destination policy), but does NOT overwrite the policyGUID, policyID, 
    other settings, and Rules of the destination policy.

    .DESCRIPTION

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER DestinationPolicyGUID
    The policy that you want to hollow out and set the new policy content for.

    .PARAMETER SourcePolicyGUID
    Source GUID of the policy you want to grab filerules, signers, cisigners, and EKUs from (to set in the destination policy.)

    .PARAMETER SourcePolicyFile
    The filepath of the XML WDAC policy you want to grab filerules, signers, cisigners, and EKUs from (to set in the destination policy.)

    .PARAMETER RetainBackup
    Keep backup of the old version of the destination policy file.
#>

    [cmdletbinding()]
    Param ( 
        $DestinationPolicyGUID,
        $SourcePolicyGUID,
        [Alias("Path","File","PolicyFile","FilePath","XMLFilePath","XMLPolicyPath")]
        $SourcePolicyFile,
        [switch]$RetainBackup
    )

    if ((-not $SourcePolicyGUID) -and (-not $SourcePolicyFile)) {
        throw "Must provide a source policy GUID or XML policy file path."
    }

    $TempPolicyPath = $null
    $BackupOldPolicy = $null
    $Connection = $null
    $Transaction = $null
    $HVCIOption = $null

    try {
        if ($ThisIsASignedModule) {
            Write-Verbose "The current file is in the SignedModules folder."
        }

        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        $HVCIOption = Get-HVCIPolicySetting -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop
        $FullPolicyPath = (Get-FullPolicyPath -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop)
        $TempPolicyPath = Get-WDACHollowPolicy -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop
        if ((-not $SourcePolicyFile) -and $SourcePolicyGUID) {
            $SourcePolicyFile = (Get-FullPolicyPath -PolicyGUID $SourcePolicyGUID -Connection $Connection -ErrorAction Stop)
        }
        $BackupOldPolicy = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
        Copy-Item $FullPolicyPath -Destination $BackupOldPolicy -Force -ErrorAction Stop
        $CurrentPolicyVersion = Get-WDACPolicyVersion -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop

        Set-UpdatedWDACPolicyContent -SourcePolicyPath $SourcePolicyFile -DestinationPolicyPath $TempPolicyPath -ErrorAction Stop | Out-Null

        Copy-Item $TempPolicyPath -Destination $FullPolicyPath -Force -ErrorAction Stop

        New-WDACPolicyVersionIncrementOne -PolicyGUID $DestinationPolicyGUID -CurrentVersion $CurrentPolicyVersion -Connection $Connection -ErrorAction Stop

        if (Test-WDACPolicySigned -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop) {
            if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $DestinationPolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Signed -Connection $Connection -ErrorAction Stop)) {
                throw "Could not set LastSignedVersion attribute on Policy $DestinationPolicyGUID"
            }
        } else {
            if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $DestinationPolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Unsigned -Connection $Connection -ErrorAction Stop)) {
                throw "Could not set LastUnsignedVersion attribute on Policy $DestinationPolicyGUID"
            }
        }

        try {
            if ($HVCIOption) {
                if ( (Get-HVCIPolicySetting -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop) -ne $HVCIOption) {
                    Set-HVCIPolicySetting -PolicyGUID $DestinationPolicyGUID -HVCIOption $HVCIOption -Connection $Connection -ErrorAction Stop
                }
            }
        } catch {
            Write-Warning $_
        }

        $Transaction.Commit()
        $Connection.Close()
        Write-Host "Successfully set the content of the destination WDAC policy." -ForegroundColor Green

        if (Test-Path $TempPolicyPath) {
            Remove-Item -Path $TempPolicyPath -Force -ErrorAction SilentlyContinue
        }
        if ((Test-Path $BackupOldPolicy) -and (-not $RetainBackup)) {
            Remove-Item -Path $BackupOldPolicy -Force -ErrorAction SilentlyContinue
        }
    } catch {
        if ($Transaction -and $Connection) {
            if ($Connection.AutoCommit -eq $false) {
                $Transaction.Rollback()
            }
        }
        if ($Connection) {
            $Connection.Close()
        }
        if ($TempPolicyPath) {
            if (Test-Path $TempPolicyPath) {
                Remove-Item -Path $TempPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
        if ($BackupOldPolicy) {
            if ( (Test-Path $BackupOldPolicy) -and $FullPolicyPath) {
                try {
                    Copy-Item -Path $BackupOldPolicy -Destination $FullPolicyPath -Force -ErrorAction Stop
                    Remove-Item -Path $BackupOldPolicy -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "Trouble restoring the old backup but it can be found at $BackupOldPolicy"
                }
            }
        }

        throw ($_ | Format-List -Property * | Out-String)
    }
}

Export-ModuleMember -Function Set-WDACPolicyContent -Alias Export-WDACPolicyContent, Write-WDACPolicyContent