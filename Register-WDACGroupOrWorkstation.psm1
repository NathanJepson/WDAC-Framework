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
    [CmdletBinding()]
    param (
        
    )

    return $null
}

function Register-WDACWorkstation {
<#
    .SYNOPSIS
    This links workstation(s) / PC(s) with the primary group that it(they) will be associated with.
    NOTE: This is the only way that you can add a new workstation! (By linking it to a group.)

    .DESCRIPTION
    This function checks what groups exist in the database, and whether a group is or isn't provided, the function prompts for a valid one. 
    Then, it will add an entry to the Devices table with the DeviceName and AllowedGroup attribute.
    
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
        [Alias("Name","Workstations","Workstation","Device","Devices","PC","Computer","Computers")]
        [string[]]$WorkstationName,
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )

    try {
        $GroupNames = Get-WDACGroups -ErrorAction Stop
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
            Write-Error "Not a valid group name."
            Write-Host ("Here are your options: " + ($GroupNamesArray -Join ",")) -ForegroundColor Yellow
            $GroupName = Read-Host -Prompt "GroupName"
        }
       
        foreach ($Name in $WorkstationName) {
            try {
                $workstation_in_db = Get-WDACDevice -DeviceName $Name
                if ($workstation_in_db) {
                    if ($workstation_in_db.AllowedGroup -eq $GroupName) {
                        throw "Device $Name already registered to group $GroupName"
                    } else {
                        throw "Device $Name is registered to a different group: $($workstation_in_db.AllowedGroup)" 
                    }
                } else {
                    if (-not (Add-WDACDevice -DeviceName $Name -AllowedGroup $GroupName -ErrorAction Stop)) {
                        throw "Failed to add Device $Name to the database."
                    }
                }
            } catch {
                Write-Warning $_
            }
        }    
    } catch {
        Write-Error $_
    }
}

function Register-WDACWorkstationAdHoc {
#This function assigns workstations to policies. This is not recommended, as it is recommended to allow policies to be applied by assigning workstations to groups.
    [CmdletBinding()]
    param (

    )

    return $null
}

Export-ModuleMember -Function Register-WDACWorkstation, Register-WDACWorkstation, Register-WDACWorkstationAdHoc