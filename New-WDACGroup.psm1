$ThisIsASignedModule = $false
if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\JSON-LocalStorageTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

function New-WDACGroup {
    <#
    .SYNOPSIS
    Create a new group which devices can be assigned to (WDAC policies are assigned to groups.)

    .DESCRIPTION
    Utilizes SQLite to be able to create another entry in the "Groups" table within the trust database.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER GroupName
    The name of this new group.

    .EXAMPLE
    New-WDACGroup Cashiers

    .EXAMPLE
    New-WDACGroup -GroupName "Top Floor"
    #>

    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )

    try {
        if ($ThisIsASignedModule) {
            Write-Verbose "The current file is in the SignedModules folder."
        }

        if (Find-WDACGroup -GroupName $GroupName -ErrorAction Stop) {
            throw "There is already a group with the name $GroupName in the database."
        }
        if (New-WDACGroup_SQL -GroupName $GroupName -ErrorAction Stop) {
            Write-Host "Group created successfully."
        } else {
            throw "Unsuccessful attempt to create new group."
        }
    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List * -Force | Out-String)
        throw $theError
    }
}

function New-WDACGroupMirror {
    <#
    .SYNOPSIS
    Create a group mirror -- where you can take another Group (MirroredGroupName), and apply it to a group (GroupName) -- which will
    allow all policies which are attached to the MirroredGroup to also be attached to the GroupName.
    (GroupMirrors are only applied when policies are deployed, and doesn't create other extraneous policy_assignments in the DB)

    .DESCRIPTION
    Creates a new entry in the group_mirrors table. GroupName is the one being applied the policies of MirroredGroupName.
    For example, you can set -GroupName Executives -MirroredGroupName Cashiers -- and this will allow the policies attached
    To the cashiers group to also be applied to the Executives group
    
    Author: Nathan Jepson
    License: MIT License

    .PARAMETER GroupName
    This is the Group which will be applied the policies attached to MirroredGroupName

    .PARAMETER MirroredGroupName
    This is the group whose policies will be attached to GroupName when Deploy-WDACPolicies is run

    .EXAMPLE
    New-WDACGroupMirror -GroupName Executives -MirroredGroupName Cashiers
    #>

    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$MirroredGroupName
    )

    try {
        if ( (-not (Find-WDACGroup -GroupName $GroupName -ErrorAction Stop)) -or (-not (Find-WDACGroup -GroupName $MirroredGroupName -ErrorAction Stop))) {
            throw "One or both of these two groups does not exist in the database."
        }

        if (Find-WDACGroupMirror -GroupName $GroupName -MirroredGroupName $MirroredGroupName -ErrorAction Stop) {
            throw "This mirrored group assignment already exists."
        }

        if (-not (Add-WDACGroupMirror -GroupName $GroupName -MirroredGroupName $MirroredGroupName -ErrorAction Stop)) {
            throw "Unable to add that mirrored group assignment to the database."
        }

        Write-Host "Mirrored group assignment created successfully."
    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List * -Force | Out-String)
        throw $theError
    }
}

Export-ModuleMember -Function New-WDACGroup
Export-ModuleMember -Function New-WDACGroupMirror