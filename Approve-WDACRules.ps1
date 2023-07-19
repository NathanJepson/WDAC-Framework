function Update-WDACConferredTrust {
    [CmdletBinding()]
    Param (
        [string]$SHA256FlatHash,
        [string]$OriginalFileName,
        [string]$MinimumVersion,
        [string]$MaximumVersion,
        [int]$PublisherIndex,
        [string]$TBSHash,
        [bool]$Trusted,
        [bool]$TrustedDriver,
        [bool]$TrustedUserMode,
        [string]$Comment,
        [string]$AllowedPolicyID,
        [string]$Level
    )
}

function Read-WDACConferredTrust {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$AppInfo,
        [PSCustomObject]$CertInfo,
        [switch]$RequireComment,
        [switch]$Purge,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string]$Level,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Fallbacks,
        [string]$GroupName,
        [string]$PolicyName,
        [string]$PolicyGUID,
        [string]$PolicyID,
        [switch]$OverrideUserorKernelDefaults,
        [ValidateSet(0,1,2,3,4,5,6,7,8,9)]
        $VersioningType,
        [switch]$AlwaysSetMinimumVersions,
        [switch]$AlwaysSetMinimumVersionsEachPolicy,
        [switch]$AdvancedVersioning,
        [switch]$ApplyVersioningOptionsToEachPolicy
    )


    #return a representation of the particular rule at the specified level or an "UNDO" command (which undoes the last trust granting action)
}

function Approve-WDACRules {
    <#
    .SYNOPSIS
    Iterate over events from pipeline--or from particular rows in the apps table if no pipeline input--and prompt user whether they trust the given apps at the provided level.

    .DESCRIPTION
    For each inputted event--or for each event in the apps table which is not specifically blocked or revoked--give the code integrity event to a dialogue box
    which will ask the user HOW they wish to trust the event; this includes at what level to trust the event (file publisher, file hash, publisher etc.) as 
    well as what specific policy to attach the trust with (which is granularized by whether the user provided a policyname, policyGUID, or policyid to this commandlet.)
    (A user may specify these items with params so they are not prompted to provide this information.)
    A user may trust a file publisher for one policy, but only trust at the level of a file hash for another policy.
    Then, the "trusted" variable in the trust database will be set (using Sqlite connection) for the provided levels.
    A user may also specify whether to trust at the kernel or usermode levels (overriding the information provided in the event, i.e., "UserMode" or "Driver").
    NOTE: This cmdlet is also when publishers and file_publishers are added to their respective tables in the database. Any hash rules on the other hand, will be trusted on the "apps" table. (Which are already in the database at this point.)
    NOTE: The version numbers that are associated with file publisher rules are governed by the VersioningType parameter.

    .PARAMETER Events
    Pipeline input of WDAC events which are piped from Register-WDACEvents

    .PARAMETER RequireComment
    When this is set, a comment must be provided when an app is trusted.

    .PARAMETER Purge
    When set, this will allow apps (i.e., audit events) to be deleted from the apps table when a considered app is trusted at a higher level (such as publisher or file publisher).
    Will not delete an audit event when it is used to set a File Hash or File Path rule.

    .PARAMETER NoOut
    When this is set, pipeline input is not sent back to the output.

    .PARAMETER Level
    What rule level you want to first consider trust at. (If not provided, the dialogue box will prompt the user.)
    Supported levels: Hash, Publisher, FilePublisher, LeafCertificate, PcaCertificate, FilePath (only applies to user-mode binaries), or FileName (not recommended for allow rules).
    
    .PARAMETER Fallbacks
    What backup rule levels to apply trust at if needed. See "Level". (If not provided, the dialogue box will NOT prompt the user for fallbacks.)

    .PARAMETER GroupName
    When this is provided, only policies linked with a particular group will be considered for linking trust.

    .PARAMETER PolicyName
    When this is provided, only one particular policy with a particular name will be considered for linking trust. 

    .PARAMETER PolicyGUID
    When this is provided, only one particular policy with a particular GUID will be considered for linking trust.

    .PARAMETER PolicyID
    When this is provided, only policies which match this provided PolicyID will be considered for linking trust.

    .PARAMETER VersioningType
    OPTIONAL: Supply an integer for different versioning behavior for file publishers. These will be written to the database (as publisher index + file name combinations)
    NOTE: VersioningTypes are NOT written to the database unless specified with this parameter (or the parameter AlwaysSetMinimumVersions is set)

        0 - GLOBAL SET MINIMUM - For a particular publisher index + file name combination, prompt the user for a [fixed] MinimumFileVersion that will be applied anytime the combination appears
        1 - GLOBAL DECREMENT MINIMUM - For a particular publisher index + file name combination, replace the MinimumFileVersion with a new one anytime a lower one appears for all appearances of the combination
        2 - GLOBAL ALWAYS SPECIFY - Regardless of which policies have a file publisher rule set, always ask the user for a specific MinimumFileVersion to apply for any instance of the publisher index + file name combination.
        3 - GLOBAL INCREMENT MINIMUM - For a particular publisher index + file name combination, replace the MinimumFileVersion with a new one anytime a GREATER one appears for all appearances of the combination
        4 - MISC GLOBAL - [Option not yet implemented]
        5 - EACH POLICY SET MINIMUM - Prompt the user whether they want a [fixed] MinimumFileVersion for each time a new publisher index + file name combination for each individual policy. 
        6 - EACH POLICY DECREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a lower one anytime a lower one is encountered
        7 - EACH POLICY ALWAYS SPECIFY - The exact same as option 2, the only difference being that when the user specifies the desired versioning for one policy, that file name + publisher index combination will be ignored for the rest of the session
        8 - EACH POLICY INCREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a HIGHER one anytime a higher one is encountered
        9 - MISC EACH POLICY - [Option not yet implemented]

    .PARAMETER OverrideUserorKernelDefaults
    This overrides the default behavior of looking at SigningScenario (for the words "Driver" or "UserMode") when deciding to trust on User Mode or Kernel Mode
    This also overrides the behavior of trusting only on UserMode by default if no SigningScenario is present.

    .PARAMETER AlwaysSetMinimumVersions
    This always sets the MinimumAllowedVersion of a new file publisher rule to "0.0.0.0" -- and there is a behavior of VersioningType 0 written to the database (with the fixed minimum of 0.0.0.0)

    .PARAMETER AlwaysSetMinimumVersionsEachPolicy
    Same as AlwaysSetMinimumVersions, but the behavior is only applied to each policy under consideration. Values are updated to the database like normal with VersioningType 5 (but fixed minimum only applied to the policies under consideration.)

    .PARAMETER AdvancedVersioning
    Gives more advanced versioning options when conveying trust.
    This runs the cmdlet as if VersioningType was always set to "2" and ignores VersioningType values from the database

    .PARAMETER ApplyVersioningOptionsToEachPolicy
    When either 1. A Versioning Type is supplied via the params or 2. Supplied via prompt -- then those options will be applied to EVERY policy under consideration. (Not necessarily every policy in the database.)
    IMPORTANT NOTE: If you want a VersioningType applied to all policies for all time, then it is recommended to set the "GlobalVersioningType" in LocalStorage.json instead. 

    .INPUTS
    [PSCustomObject] Result of Register-WDACEvents (OPTIONAL)

    .OUTPUTS
    Pipes out a replica of the inputs if you still need them.

    .EXAMPLE
    TODO: EXAMPLES!

    .EXAMPLE
    TODO: EXAMPLES!

    .EXAMPLE
    TODO: EXAMPLES!

    .EXAMPLE
    TODO: EXAMPLES!
    #>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [PSCustomObject[]]$Events,
        [switch]$RequireComment,
        [switch]$Purge,
        [switch]$NoOut,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string]$Level,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [string[]]$Fallbacks,
        [string]$GroupName,
        [string]$PolicyName,
        [string]$PolicyGUID,
        [string]$PolicyID,
        [Alias("NoDefault","Override")]
        [switch]$OverrideUserorKernelDefaults,
        [ValidateNotNullOrEmpty()]
        [ValidateSet(0,1,2,3,5,6,7,8)]
        $VersioningType,
        [Alias("AlwaysMin","SetMin","SetMinimum")]
        [switch]$AlwaysSetMinimumVersions,
        [Alias("SetMinPerPolicy","SetMinPolicy","AlwaysMinPerPolicy","PolicyMin")]
        [switch]$AlwaysSetMinimumVersionsEachPolicy,
        [switch]$AdvancedVersioning,
        [Alias("EachPolicyVersioning","PolicyVersioning")]
        [switch]$ApplyVersioningOptionsToEachPolicy
    )

    begin {
        if ($VersioningType -ne 0 -and $AlwaysSetMinimumVersions) {
            Write-Error "Cannot set a non-zero VersioningType when AlwaysSetMinimumVersions is set."
            return;
        }

        if ($VersioningType -ne 5 -and $AlwaysSetMinimumVersionsEachPolicy) {
            Write-Error "Cannot set a non-zero VersioningType when AlwaysSetMinimumVersionsEachPolicy is set."
        }
    
        if ($Fallbacks -and -not $Level) {
            throw "Cannot provide fallbacks without providing a level. (This would be the preferred or default level.)"
        }
    }

    process {

        $ErrorCount = 0
        if (-not $Events) {
            try {
                $Events = Get-WDACAppsToSetTrust -ErrorAction Stop
            } catch {
                throw $_;
                return;
            }
        }
     
        $CertInfoHashTable = {}
        foreach ($Event in $Events) {
            try {
                if ($ErrorCount -ge 4) {
                    Write-Error "Error count exceeding a reasonable amount. Terminating."
                    return
                }
                $CertInfo = Expand-WDACApp -Sha256FlatHash $Event.SHA256FlatHash -AddPublisher:($Level -eq "Publisher" -or $Fallbacks -contains "Publisher" -or ($Level -eq "FilePublisher" -or $Fallbacks -contains "FilePublisher")) -ErrorAction Stop
                $CertInfoHashTable[$($App.SHA256FlatHash)] = $CertInfo
            } catch {
                Write-Verbose $_
                Write-Warning "Failed to grab app information from the database OR in adding a publisher rule -- for app with hash $($App.SHA256FlatHash)."
                $ErrorCount += 1
            }
        }

        $RulesToTrust = @()
        $PreviousEvent = $null
        foreach ($Event in $Events) {
            try {
                if ($ErrorCount -ge 4) {
                    Write-Error "Error count exceeding a reasonable amount. Terminating."
                    return
                }
                $RuleOrUndo = Read-WDACConferredTrust #TODO Params
                if ($RuleOrUndo -eq "Undo") {
                    #TODO - Remove from RulesToTrust, Undo Database Transaction for added File Publisher, While Loop (no 2 undos in a row)
                } else {
                    $RulesToTrust.Add($RuleOrUndo)
                }

                $PreviousEvent = $Event
            } catch {
                Write-Verbose $_
                Write-Warning "Failed to confer trust for a rule associated with the app containing this hash: $($App.SHA256FlatHash)"
                $ErrorCount += 1
            }
        }

        foreach ($Rule in $RulesToTrust) {
            Update-WDACConferredTrust #TODO Params
        }
    }

    end {
        if (-not $NoOut) {
            if ($Events) {
                return $Events
            }
        }
    }
}