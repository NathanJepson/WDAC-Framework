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

    


}


function Restore-WDACWorkstations {
    <#
    .SYNOPSIS
    For computers which were initially not part of a group of test computers -- or for computers which were not remotely available or couldn't
    apply the most recent policy version -- bring them up to date with the the policy specified.

    .DESCRIPTION
    TODO

    .PARAMETER PolicyGUID
    ID of the policy (NOT the alternate ID which WDAC policies also have, although you can use the alias "PolicyID" for this parameter)

    .PARAMETER PolicyName
    Name of the policy (exact)

    Author: Nathan Jepson
    License: MIT License
    #>
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Alias("PolicyID","id")]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName
    )
}