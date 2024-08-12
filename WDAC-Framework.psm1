$Modules = @("Resources\SQL-TrustDBTools.psm1", "Resources\JSON-LocalStorageTools.psm1", "WDACAuditing\WDACAuditing.psm1","Resources\Microsoft-Recommended-Rules.psm1","Resources\Code-Signing-Tools.psm1","Register-WDACGroupOrWorkstation.psm1","Resources\File-Publisher-Helpers.psm1","Resources\SQL-TrustDBTools_Part2.psm1","Resources\WorkingPolicies-and-DB-IO.psm1","Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1","Resources\SQL-TrustDBTools_Part3.psm1","Resources\Copy-WDACFileScanner.psm1","Resources\WDACFileScanner.psm1","Resources\Remove-EFIWDACPolicy.psm1","Resources\Invoke-ActivateAndRefreshWDACPolicy.psm1","Resources\Restart-WDACDevices.psm1","Resources\Copy-StagedWDACPolicies.psm1")

$SubModules = @("Import-WDACRule.psm1","Import-WDACPolicy.psm1","New-WDACGroup.psm1","Register-WDACEvents.psm1","Merge-TrustedWDACRules.psm1","Edit-WDACPolicy.psm1","New-WDACPolicy.psm1","Get-WDACEvents.psm1","Resources\Copy-WDACAuditing.psm1","New-WDACTrustDB.psm1","Get-WDACFiles.psm1","Set-SignedPowerShellModules.psm1","UsefulCmdlets\Get-MiscWDACEvents.psm1","UsefulCmdlets\Update-WDACRuleIDs.psm1","Remove-WDACRule.psm1","Approve-WDACRules.psm1","Deploy-WDACPolicies.psm1","UsefulCmdlets\Set-WDACDeviceDeferred.psm1","UsefulCmdlets\Convert-CIToolVersion.psm1","UsefulCmdlets\Update-RemoteModules.psm1","UsefulCmdlets\Get-BootStartDrivers.psm1","Resources\Test-ValidWDACSignedPolicySignature.psm1")

for ($i=0; $i -lt $Modules.Count; $i++) {
    if (Test-Path (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($Modules[$i])")) {
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($Modules[$i])")
    } else {
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $($Modules[$i]))
    }
}

for ($i=0; $i -lt $SubModules.Count; $i++) {
    if (Test-Path (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($SubModules[$i])")) {
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "SignedModules\$($SubModules[$i])")
    } else {
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $($SubModules[$i]))
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
