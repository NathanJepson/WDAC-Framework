function Deploy-WDACPolicies {
    <#
    .SYNOPSIS
    This function deploys WDAC policies specified by parameter input -- 
    ONLY IF the latest version hasn't yet been deployed -- signs them (if applicable)
    and copies them to the relevant machines which have those policies assigned.
    Then a RefreshPolicy action is enacted on that machine.

    .DESCRIPTION
    This function determines what machines have the designated policy assigned to them, by checking the policy "pillar" attribute, 
    as well as group assignments and ad-hoc assignments. (A policy set as a pillar is deployed to every device listed in the trust database.)
    It signs policies which need to be signed. (Using the SignTool.)
    Then, that designated policy (the signed / unsigned .CIP file) is deployed to each machine (ONLY IF the DB shows that that version has not been deployed yet.)
    For machines which cannot have their policy updated, the last deployed policy is recorded -- with all its parameters, in the deferred_policies table, 
    and an entry for that particular device is made in the deferred_policies_assignments table.
    Then, if a policy is signed, it is also placed in the UEFI partition for the machine.
    Finally, a refresh policy is performed on the relevant machine (if the machine runs on Windows 11, the CiTool is used, otherwise, RefreshPolicy.exe is used.)
    When a selection of TestComputers is designated, the remaining computers which are not test computers are set with the policy_deferring flag until the 
    Restore-WDACWorkstations cmdlet is used to bring those computers up-to-date with the most recent policy version.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER PolicyGUID
    ID of the policy (NOT the alternate ID which WDAC policies also have, although you can use the alias "PolicyID" for this parameter)

    .PARAMETER PolicyName
    Name of the policy (exact)

    .PARAMETER Local
    Use this switch if you merely want to update the policy on your current machine (local)

    .PARAMETER TestComputers
    Specify test computers where you would like to deploy the policy first. First, a check is performed if a test computer is actually assigned the particular policy.
    Once you can verify that a policy was successfully deployed on the test machines, then run the Restore-WDACWorkstations cmdlet to deploy the relevant policy
    to the remaining machines which have the policy assigned.

    .PARAMETER TestForce
    Force deployment of policy to machines -- even if they are not assigned the relevant policy. (Only if "TestComputers" is provided.)

    .EXAMPLE
    TODO

    .EXAMPLE
    TODO
    #>    
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Alias("PolicyID","id")]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,
        [switch]$Local,
        [string[]]$TestComputers,
        [Alias("Force")]
        [switch]$TestForce
    )
    
    if ($PolicyName -and $PolicyGUID) {
        throw "Cannot provide both a policy name and policy GUID."
    }

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        
        if ($PolicyName) {
            $PolicyInfo = Get-WDACPolicyByName -PolicyName $PolicyName -Connection $Connection
            $PolicyGUID = $PolicyInfo.PolicyGUID
        } elseif ($PolicyGUID) {
            $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection
        }
    
        $ComputerMap = Get-WDACDevicesNeedingWDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

    } catch {
        throw $_
    }
}

function Restore-WDACWorkstations {
    <#
    .SYNOPSIS
    For computers which were initially not part of a group of test computers -- or for computers which were not remotely available or couldn't
    apply the most recent policy version -- bring them up to date with the the policy specified.

    .DESCRIPTION
    This cmdlet will remove workstations / PCs from "deferred" status if it can successfully deploy the newest policy designated by PolicyGUID to the applicable workstations.
    If the "WorkstatioNName" parameter does not specify a workstation, then all devices with a deferred status and associated with a policy.
    Many of the same elements of deploying policies is borrowed from the Deploy-Policies cmdlet.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER PolicyGUID
    ID of the policy (NOT the alternate ID which WDAC policies also have, although you can use the alias "PolicyID" for this parameter)

    .PARAMETER PolicyName
    Name of the policy (exact)

    .PARAMETER WorkstationName
    Specify this parameter if you only want to restore particular workstations to the current WDAC policy.

    .EXAMPLE
    TODO

    .EXAMPLE
    TODO

    #>
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Alias("PolicyID","id")]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [Alias("Workstations","Workstation","Device","Devices","PC","Computer","Computers")]
        [string[]]$WorkstationName
    )

    if ($PolicyName -and $PolicyGUID) {
        throw "Cannot provide both a policy name and policy GUID."
    }

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        
        if ($PolicyName) {
            $PolicyInfo = Get-WDACPolicyByName -PolicyName $PolicyName -Connection $Connection
            $PolicyGUID = $PolicyInfo.PolicyGUID
        } elseif ($PolicyGUID) {
            $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection
        }
    
        #Deferred flag is set here, unlike the above cmdlet
        $ComputerMapTemp = Get-WDACDevicesNeedingWDACPolicy -PolicyGUID $PolicyGUID -Deferred -Connection $Connection -ErrorAction Stop
        $ComputerMap = @{}
        if ($WorkstationName) {
            foreach ($Entry in $ComputerMapTemp.GetEnumerator()) {
                if ($WorkstationName -contains $Entry.Name) {
                    $ComputerMap += @{$Entry.Name = $Entry.Value}
                }
            }
        }
    } catch {
        throw $_
    }
}