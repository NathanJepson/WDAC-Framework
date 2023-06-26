$Modules = @("Resources\JSON-LocalStorageTools.psm1", "WDACAuditing\WDACAuditing.psm1", "Resources\SQL-TrustDBTools.psm1")

$Scripts = @("Set-SignedPowerShellModules.ps1","Add-WDACTrustDB.ps1","Get-WDACEvents.ps1","Resources\Copy-WDACAuditing.ps1")

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