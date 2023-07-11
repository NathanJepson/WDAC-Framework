filter Approve-WDACRules {
    <#
    .SYNOPSIS
    Iterate over events from pipeline--or from particular rows in the apps table if no pipeline input--and prompt user whether they trust the given apps at the provided level.

    .DESCRIPTION
    For each inputted event--or for each event in the apps table which is not specifically blocked or revoked--give the code integrity event to a dialogue box
    which will ask the user how they wish to trust the event; this includes at what level to trust the event (file publisher, file hash, publisher etc.) as 
    well as what specific policy to attach the trust with (which is granularized by whether the user provided a policyname, policyGUID, or policyid to this commandlet.)
    A user may trust a file publisher for one policy, but only trust at the level of a file hash for another policy.
    Then, the "trusted" variable in the trust database will be set (using Sqlite connection) for the provided levels.
    A user may also specify whether to trust at the kernel or usermode levels (overriding the information provided in the event, i.e., "UserMode" or "Driver").

    .PARAMETER Events
    Pipeline input of WDAC events which are piped from Register-WDACEvents

    .PARAMETER RequireComment
    When this is set, a comment must be provided when an app is trusted.

    .PARAMETER NoOut
    When this is set, pipeline input is not sent back to the output.

    .PARAMETER Level
    What rule level you want to first consider trust at. (If not provided, the dialogue box will prompt the user.)
    
    .PARAMETER Fallbacks
    What backup rule levels to condier applying trust at. (If not provided, the dialogue box will NOT prompt the user for fallbacks.)

    .PARAMETER GroupName
    When this is provided, only policies linked with a particular group will be considered for linking trust.

    .PARAMETER PolicyName
    When this is provided, only one particular policy with a particular name will be considered for linking trust. 

    .PARAMETER PolicyGUID
    When this is provided, only one particular policy with a particular GUID will be considered for linking trust.

    .PARAMETER PolicyID
    When this is provided, only policies which match this provided PolicyID will be considered for linking trust.

    .PARAMETER OverrideUserorKernelDefaults
    This overrides the default behavior of looking at SigningScenario (for the words "Driver" or "UserMode") when deciding to trust on User Mode or Kernel Mode
    This also overrides the behavior of trusting only on UserMode by default if no SigningScenario is present.

    .INPUTS
    [PSCustomObject] Result of Register-WDACEvents (OPTIONAL)

    .OUTPUTS
    Pipes out a replica of the inputs if you still need them.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [PSCustomObject[]]$Events,
        [switch]$RequireComment,
        [switch]$NoOut,
        [string]$Level,
        [string[]]$Fallbacks,
        [string]$GroupName,
        [string]$PolicyName,
        [string]$PolicyGUID,
        [string]$PolicyID,
        [switch]$OverrideUserorKernelDefaults
    )

   #TODO: Implement trust granting dialogue function and Sqlite calls
   
    if (-not $NoOut) {
        if ($Events) {
            return $Events
        }
    }
}