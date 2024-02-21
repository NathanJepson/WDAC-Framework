$Modules = @("Resources\SQL-TrustDBTools.psm1", "Resources\JSON-LocalStorageTools.psm1", "WDACAuditing\WDACAuditing.psm1","Resources\Microsoft-Recommended-Rules.psm1","Resources\Code-Signing-Tools.psm1","Register-WDACGroupOrWorkstation.psm1","Resources\File-Publisher-Helpers.psm1","Resources\SQL-TrustDBTools_Part2.psm1","Resources\WorkingPolicies-and-DB-IO.psm1","Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1","Resources\SQL-TrustDBTools_Part3.psm1")

$Scripts = @("Set-SignedPowerShellModules.ps1","New-WDACTrustDB.ps1","Get-WDACEvents.ps1","Resources\Copy-WDACAuditing.ps1","New-WDACGroup.ps1","Register-WDACEvents.ps1","New-WDACPolicy.ps1","Approve-WDACRules.ps1","Import-WDACPolicy.ps1","Merge-TrustedWDACRules.ps1","Edit-WDACPolicy.ps1","Deploy-WDACPolicies.ps1","Resources\Copy-StagedWDACPolicies.ps1","Resources\Invoke-ActivateAndRefreshWDACPolicy.ps1","Resources\Restart-WDACDevices.ps1","Resources\Remove-EFIWDACPolicy.ps1","Remove-WDACRule.ps1","Import-WDACRule.ps1","UsefulCmdlets\Rename-WDACRuleIDs.ps1")

for ($i=0; $i -lt $Modules.Count; $i++) {
    if (Test-Path (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($Modules[$i])")) {
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($Modules[$i])")
    } else {
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $($Modules[$i]))
    }
}

for ($i=0; $i -lt $Scripts.Count; $i++) {
    if (Test-Path (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($Scripts[$i])")) {
        . (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($Scripts[$i])")
    } else {
        . (Join-Path -Path $PSScriptRoot -ChildPath $($Scripts[$i]))
    }
}

function Get-SQLiteAssemblyPath {
    return ((Get-LocalStorageJSON -ErrorAction Stop)."SqliteAssembly")
}

$SqliteAssembly = Get-SQLiteAssemblyPath -ErrorAction Stop
try {
    #This could throw off some EDR or anti-virus solutions
    if ((Split-Path $SqliteAssembly -Extension -ErrorAction Stop) -eq ".dll") {
        [Reflection.Assembly]::LoadFile($SqliteAssembly) | Out-Null
    } else {
        throw "You must set the SqliteAssembly variable in LocalStorage.json to the valid path of the Sqlite .dll binary. `nRun the WDAC-Framework-Setup.ps1 script to set all required variables in this JSON file.";
    }
} catch [NotSupportedException] {
    throw "This Sqlite binary is not supported in this version of PowerShell.";
} catch {
    throw "You must set the SqliteAssembly variable in LocalStorage.json to the valid path of the Sqlite .dll binary. `nRun the WDAC-Framework-Setup.ps1 script to set all required variables in this JSON file.";
}