if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    Write-Verbose "The current file is in the SignedModules folder."
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

function Register-WDACGroup {
    <#
    .SYNOPSIS
    ALIAS: Register-WDACPolicy
    This assigns a particular PolicyID (or PolicyIDs) to a Group. This means that devices that are assigned to this group will also be assigned those policies.

    .DESCRIPTION
    For each policy id supplied, an entry is added to the policy_assignments.
    If there are no policy ids or GroupName supplied, then the user is prompted for which one they would like.
    
    Author: Nathan Jepson
    License: MIT License
    
    .PARAMETER PolicyID
    PolicyID or PolicyIDs that you would like to be linked to the GroupName. (These are GUIDs, not those other custom Policy IDs.)

    .PARAMETER PolicyName
    If you do not wish to supply PolicyID(s), then you can merely supply the names of the policies you would like linked.

    .PARAMETER GroupName
    The Group that this (these) policy (policies) will be linked to.

    .EXAMPLE
    Register-WDACGroup -PolicyID "BAC7A36F-CFED-4A29-A4E3-C837067B5898","90E75911-083A-42A7-AB90-8FF50D904ADA"

    .EXAMPLE
    Register-WDACGroup -Name AllowAdobe,DenyWireshark -GroupName Cashiers

    .EXAMPLE
    Register-WDACGroup
    #>
    [CmdletBinding()]
    [Alias('Register-WDACPolicy')]
    param (
        [ValidateNotNullOrEmpty()]
        [Alias("ID","IDs","PolicyGUID","GUID","GUIDs","PolicyGUIDs")]
        [string[]]$PolicyID,
        [ValidateNotNullOrEmpty()]
        [string[]]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )

    try {
        if ($PolicyID -and $PolicyName) {
            throw "You must provider Policy names or Policy IDs, but not both."
        } elseif ($PolicyID -or $PolicyName) {
            if ($PolicyID) {
                foreach ($thisID in $PolicyID) {
                    if (-not (Find-WDACPolicy -PolicyGUID $thisID -ErrorAction Stop)) {
                        throw "There is no policy with ID $thisID"
                    }
                }
            } elseif ($PolicyName) {
                #$PolicyID = @()
                $PoliciesWithNames = Get-WDACPoliciesGUIDandName -ErrorAction Stop
                foreach ($thisName in $PolicyName) {
                    if (-not (Find-WDACPolicyByName -PolicyName $thisName -ErrorAction Stop)) {
                        throw "There is no policy with name $thisName"
                    }
                    $PolicyID += ($PoliciesWithNames | Where-Object {$_.PolicyName -eq $thisName} | Select-Object PolicyGUID).PolicyGUID
                }
            }
        } else {
        #Case: No policy IDs or names are provided
            $PoliciesWithNames = Get-WDACPoliciesGUIDandName -ErrorAction Stop
            Write-Host "What policy would you like to assign to a group?" -ForegroundColor Green
            Write-Host "Here are your options (please use GUID):" -ForegroundColor Yellow
            $PoliciesWithNames | Select-Object PolicyGUID,PolicyName | Out-Host
            $PolicyIDInput = Read-Host -Prompt "PolicyGUID"
            while (-not (Find-WDACPolicy -PolicyGUID $PolicyIDInput -ErrorAction Stop)) {
                Write-Host "Not a valid PolicyGUID." -ForegroundColor Red
                Write-Host "Here are your options (please use GUID): " -ForegroundColor Yellow
                $PoliciesWithNames | Select-Object PolicyGUID,PolicyName | Out-Host
                $PolicyIDInput = Read-Host -Prompt "PolicyGUID"
            }
            $PolicyID = $PolicyIDInput
        }

        $GroupNames = Get-WDACGroups -ErrorAction Stop
        $GroupNamesArray = @()
        for ($i=0; $i -lt $GroupNames.Count; $i++) {
            $GroupNamesArray += $GroupNames[$i].GroupName
        }
        if (-not $GroupName) {
            Write-Host "What group name should this (these) policy (policies) be assigned to?" -ForegroundColor Green
            Write-Host ("Here are your options: " + ($GroupNamesArray -Join ","))  -ForegroundColor Yellow
            $GroupName = Read-Host -Prompt "GroupName"
        }
    
        while (-not ($GroupNamesArray -contains $GroupName)) {
            Write-Host "Not a valid group name." -ForegroundColor Red
            Write-Host ("Here are your options: " + ($GroupNamesArray -Join ",")) -ForegroundColor Yellow
            $GroupName = Read-Host -Prompt "GroupName"
        }

        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()

        foreach ($thisPolicy in $PolicyID) {
            if (-not (Add-WDACPolicyAssignment -GroupName $GroupName -PolicyGUID $thisPolicy -Connection $Connection -ErrorAction Stop)) {
                throw "Unable to add Policy assignment of policy $thisPolicy to group $GroupName to the database."
            }
        }

        $Transaction.Commit()
        $Connection.Close()
        Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue

        Write-Host "Policies assigned successfully to group $GroupName"

    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List * -Force | Out-String)
        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }
        throw $theError
    }
}

function Register-WDACWorkstation {
<#
    .SYNOPSIS
    This links workstation(s) / PC(s) with the primary group that it(they) will be associated with.
    NOTE: This is the only way that you can add a new workstation! (By linking it to a group.)

    .DESCRIPTION
    This function checks what groups exist in the database, and whether a group is or isn't provided, the function prompts for a valid one. 
    Then, it will add an entry to the Devices table with the DeviceName and AllowedGroup attribute.

    Author: Nathan Jepson
    License: MIT License
    
    .PARAMETER WorkstationName
    Name of workstation or multiple workstations. Device names must be hostnames that can be used to start a Remote-PSSession (WinRM). 

    .PARAMETER GroupName
    Name of the group to assign the device(s) to.

    .EXAMPLE
    Register-WDACWorkstation -Device PC1,PC2

    .EXAMPLE
    Register-WDACWorkstation -WorkstationName PC1 -GroupName Cashiers
#>
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Workstations","Workstation","Device","Devices","PC","Computer","Computers")]
        [string[]]$WorkstationName,
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )

    try {
        $GroupNames = Get-WDACGroups -ErrorAction Stop

        if ($null -eq $GroupNames -or ($GroupNames.Count -le 0)) {
            throw "Create some groups before registering a new workstation."
        }

        $GroupNamesArray = @()
        for ($i=0; $i -lt $GroupNames.Count; $i++) {
            $GroupNamesArray += $GroupNames[$i].GroupName
        }
        if (-not $GroupName) {
            Write-Host "What group name should these workstation(s) be assigned to?" -ForegroundColor Green
            Write-Host ("Here are your options: " + ($GroupNamesArray -Join ","))  -ForegroundColor Yellow
            $GroupName = Read-Host -Prompt "GroupName"
        }

        while (-not ($GroupNamesArray -contains $GroupName)) {
            Write-Host "Not a valid group name." -ForegroundColor Red
            Write-Host ("Here are your options: " + ($GroupNamesArray -Join ",")) -ForegroundColor Yellow
            $GroupName = Read-Host -Prompt "GroupName"
        }
       
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()

        foreach ($Name in $WorkstationName) {
            try {
                $workstation_in_db = Get-WDACDevice -DeviceName $Name -ErrorAction Stop
                if ($workstation_in_db) {
                    if ($workstation_in_db.AllowedGroup -eq $GroupName) {
                        throw "Device $Name already registered to group $GroupName"
                    } else {
                        throw "Device $Name is registered to a different group: $($workstation_in_db.AllowedGroup)" 
                    }
                } else {
                    if (-not (Add-WDACDevice -DeviceName $Name -AllowedGroup $GroupName -Connection $Connection -ErrorAction Stop)) {
                        throw "Failed to add Device $Name to the database."
                    }
                }
            } catch {
                Write-Warning $_
            }
        }
        
        $Transaction.Commit()
        $Connection.Close()
        Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue

        Write-Host "Workstations successfully instantiated and assigned to group $GroupName"

    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List * -Force | Out-String)
        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }

        throw $theError
    }
}

function Register-WDACWorkstationAdHoc {
<#
    .SYNOPSIS
    This function assigns workstations to policies. This is not recommended, as it is recommended to allow policies to be applied by assigning workstations to groups.

    .DESCRIPTION
    This functions contains a similar method of selecting a policy if it is not provided -- similar to Register-WDACGroup
    WorkstationName is required, but you can provide more than one workstation name at once. 
    You cannot provide more than one policy at once.

    Author: Nathan Jepson
    License: MIT License

    .EXAMPLE
    Register-WDACWorkstationAdHoc -Devices PC1,PC2

    .EXAMPLE
    Register-WDACWorkstationAdHoc -Computer PC1 -PolicyName "Cashiers_Policy"

    .EXAMPLE
    Register-WDACWorkstationAdHoc -WorkstationName PC1 -PolicyID "fd04c607-e1d9-4416-954a-b6f3817c9d10"
#>
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Name","Workstations","Workstation","Device","Devices","PC","Computer","Computers","PCs")]
        [string[]]$WorkstationName,
        [ValidateNotNullOrEmpty()]
        [Alias("ID","IDs","PolicyGUID","GUID","GUIDs","PolicyGUIDs")]
        [string]$PolicyID,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName
    )

    $Connection = $null
    $Transaction = $null

    try {
        foreach ($PC in $WorkstationName) {
            if (-not (Get-WDACDevice -DeviceName $PC -ErrorAction Stop)) {
                throw "No device in the DB exists with name $PC"
            }
        }

        if ($PolicyID -and $PolicyName) {
            throw "You must provider Policy names or Policy IDs, but not both."
        } elseif ($PolicyID -or $PolicyName) {
            if ($PolicyID) {
                if (-not (Find-WDACPolicy -PolicyGUID $PolicyID -ErrorAction Stop)) {
                    throw "There is no policy with ID $PolicyID"
                }
            } elseif ($PolicyName) {
                if (-not (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop)) {
                    throw "There is no policy with name $PolicyName"
                }
                $PolicyID = (Get-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop).PolicyGUID
            }
        } else {
        #Case: No policy IDs or names are provided
            $PoliciesWithNames = Get-WDACPoliciesGUIDandName -ErrorAction Stop
            Write-Host "What policy would you like to assign to a group?" -ForegroundColor Green
            Write-Host "Here are your options (please use GUID):" -ForegroundColor Yellow
            $PoliciesWithNames | Select-Object PolicyGUID,PolicyName | Out-Host
            $PolicyIDInput = Read-Host -Prompt "PolicyGUID"
            while (-not (Find-WDACPolicy -PolicyGUID $PolicyIDInput -ErrorAction Stop)) {
                Write-Host "Not a valid PolicyGUID." -ForegroundColor Red
                Write-Host "Here are your options (please use GUID): " -ForegroundColor Yellow
                $PoliciesWithNames | Select-Object PolicyGUID,PolicyName | Out-Host
                $PolicyIDInput = Read-Host -Prompt "PolicyGUID"
            }
            $PolicyID = $PolicyIDInput
        }

        foreach ($PC in $WorkstationName) {
            if (Find-WDACPolicyAdHocAssignment -PolicyGUID $PolicyID -DeviceName $PC -ErrorAction Stop) {
                throw "Workstation $PC is already assigned to policy $PolicyID"
            }
        }

        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()

        foreach ($PC in $WorkstationName) {
            if (-not (Add-WDACPolicyAdHocAssignment -DeviceName $PC -PolicyGUID $PolicyID -Connection $Connection -ErrorAction Stop)) {
                throw "Unable to add Policy assignment of policy $PolicyID  to device $PC to the database."
            }
        }

        $Transaction.Commit()
        $Connection.Close()
        Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue

        Write-Host "Policy $PolicyID assigned successfully to the designated device(s)."

    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List * -Force | Out-String)
        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }
        throw $theError
    }

    return $null
}

Export-ModuleMember -Function Register-WDACWorkstation, Register-WDACWorkstationAdHoc
Export-ModuleMember -Function Register-WDACGroup -Alias Register-WDACPolicy