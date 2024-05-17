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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part3.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part3.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools_Part3.psm1")
}

function Set-WDACDeviceDeferred {
    <#
    .SYNOPSIS
    Put a device into a deferred state (on a specific policy)

    .DESCRIPTION
    This will set the deferred flag on a device in the SQL database, and add a relevant deferred-policy-assignment entry
    in the database for the specific policy GUID provided.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER PolicyGUID
    GUID of the Policy

    .PARAMETER DeviceName
    Hostname of the device.

    .PARAMETER Comment
    What comment about the deferrment you want to provide, e.g., "We are waiting for this condition to be met before deploying
    more WDAC policies on this device."
    #>

    [cmdletbinding()]
    Param ( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("PC","Computer","Device")]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
        [string]$Comment
    )

    if ($ThisIsASignedModule) {
        Write-Verbose "The current file is in the SignedModules folder."
    }

    if (-not $Comment) {
        $Comment = "Device was deferred using Set-WDACDeviceDeferred cmdlet."
    }

    try {

        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()

        if (-not (Set-WDACDeviceDeferredStatus -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop)) {
            throw "Unable to update deferred status for $DeviceName"
        }
    
        if (-not (Test-PolicyDeferredOnDevice -PolicyGUID $PolicyGUID -WorkstationName $DeviceName -Connection $Connection -ErrorAction Stop)) {
            $PolicyVersion = Get-WDACPolicyLastDeployedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            $DeferredPolicy = $null
            if (Test-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $PolicyVersion -Connection $Connection -ErrorAction Stop) {
                $DeferredPolicy = Get-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
            } else {
                if (-not (Add-DeferredWDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                    throw "Cannot add deferred WDAC policy of GUID $PolicyGUID and version $PolicyVersion"
                }
                $DeferredPolicy = Get-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
            }
    
            if (-not (Add-DeferredWDACPolicyAssignment -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -DeviceName $DeviceName -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
                throw "Unable to add deferred policy assignment of deferred policy index $($DeferredPolicy.DeferredPolicyIndex) to device $DeviceName"
            }
        }

        $Transaction.Commit()
    } catch {
        Write-Verbose ($_ | Format-List -Property * | Out-String)
        throw $_
    }
}


Export-ModuleMember -Function Set-WDACDeviceDeferred