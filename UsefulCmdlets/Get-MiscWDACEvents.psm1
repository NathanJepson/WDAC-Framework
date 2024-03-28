
function Get-MiscWDACEvents {
    <#
    .SYNOPSIS
    Get broad-spectrum WDAC events from CodeIntegrity and AppLocker logs on Windows machines.

    .DESCRIPTION
    There are three ways to get events:

    WDAC Basic Events - Event IDs: 3034,3064-3065,3076-3077,3079-3082,3090,3104,3111,3114,8002,8028-8029,8036,8039-8040
    *8002 might give many results in some cases. I've made it so you have to use -Verbose if you want to see these.

    WDAC Policy Events - Event IDs: 3095-3103,3105

    WDAC Misc Events - Event IDs: 3001,3002,3004,3010,3011,3023,3024,3026,3032,3033,3036,3074,3084,3085,3086,3108,3110,3112
    *3004 Might give many results in some cases

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER RemoteMachine
    The single machine to grab event logs from. (Currently doesn't support multiple machines.)

    .PARAMETER WDACBasicEvents
    Event IDs: 3034,3064-3065,3076-3077,3079-3082,3090,3104,3111,3114,8028-8029,8036,8039-8040 -- and 8002 if -verbose is used

    .PARAMETER WDACPolicyEvents
    Event IDs: 3095-3103,3105

    .PARAMETER WDACMiscEvents
    Event IDs: 3001,3002,3004,3010,3011,3023,3024,3026,3032,3033,3036,3074,3084,3085,3086,3108,3110,3112

    .PARAMETER EventIDsToExclude
    If you want to exclude a particular event ID, use this (int array input).

    .PARAMETER MaxEvents
    How many events you want returned.

    .PARAMETER Oldest
    If you want to return the oldest events first, use this switch.
    #>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Alias("Computer","Machine","Device","PC")]
        [string]$RemoteMachine,
        [Alias("WDACBasic")]
        [switch]$WDACBasicEvents,
        [Alias("WDACPolicy")]
        [switch]$WDACPolicyEvents,
        [Alias("WDACMisc")]
        [switch]$WDACMiscEvents,
        [Alias("Exclude")]
        [int[]]$EventIDsToExclude,
        [Int64]$MaxEvents,
        [switch]$Oldest
    )

    if (-not ($WDACBasicEvents -or $WDACPolicyEvents -or $WDACMiscEvents)) {
        throw "Select either -WDACBasicEvents, -WDACPolicyEvents, or -WDACMiscEvents"
    }

    if (($WDACBasicEvents -and $WDACPolicyEvents) -or ($WDACBasicEvents -and $WDACMiscEvents) -or ($WDACPolicyEvents -and $WDACMiscEvents)) {
        #The github issue detailing the array size limit for EventIDs is here: https://github.com/PowerShell/PowerShell/issues/12303
        throw "Because of limitations in a filter hashtable, you can only select -WDACBasicEvents, -WDACPolicyEvents, or -WDACMiscEvents, but not a combination of them."
    }

    if ($VerbosePreference) {
        $WDACBasicEventIDs = 3064..3065 + 3034 + 3076..3077 + 3079..3082 + 3090 + 3104 + 3111 + 3114 + 8002 + 8028..8029 + 8036 + 8039..8040
    } else {
        $WDACBasicEventIDs = 3064..3065 + 3034 + 3076..3077 + 3079..3082 + 3090 + 3104 + 3111 + 3114 + 8028..8029 + 8036 + 8039..8040
    }

    $WDACPolicyEventIDs = 3095..3103 + 3105
    $WDACMiscEventIDs = 3001..3002 + 3004 + 3010..3011 + 3023..3024 + 3026 + 3032..3033 + 3036 + 3074 + 3084..3086 + 3108 + 3110 + 3112
    
    foreach ($ToExclude in $EventIDsToExclude) {
        if ($WDACBasicEventIDs -contains $ToExclude) {
            $WDACBasicEventIDs = $WDACBasicEventIDs | Where-Object {$_ -ne $ToExclude}
        }
        if ($WDACPolicyEventIDs -contains $ToExclude) {
            $WDACPolicyEventIDs = $WDACPolicyEventIDs | Where-Object {$_ -ne $ToExclude}
        }
        if ($WDACMiscEventIDs -contains $ToExclude) {
            $WDACMiscEventIDs = $WDACMiscEventIDs | Where-Object {$_ -ne $ToExclude}
        }
    }

    $EventsToUse = $null
    if ($WDACBasicEvents) {
        $EventsToUse = $WDACBasicEventIDs
    } elseif ($WDACPolicyEvents) {
        $EventsToUse = $WDACPolicyEventIDs
    } elseif ($WDACMiscEvents) {
        $EventsToUse = $WDACMiscEventIDs
    }

    if (-not $RemoteMachine) {
        if ($MaxEvents) {
            return (Get-WinEvent -FilterHashtable @{ Logname = "Microsoft-Windows-CodeIntegrity/Operational","Microsoft-Windows-AppLocker/EXE and DLL","Microsoft-Windows-AppLocker/MSI and Script","Microsoft-Windows-AppLocker/Packaged app-Deployment","Microsoft-Windows-AppLocker/Packaged app-Execution"; ID=$EventsToUse} -MaxEvents $MaxEvents -Oldest:$Oldest)
        } else {
            return (Get-WinEvent -FilterHashtable @{ Logname = "Microsoft-Windows-CodeIntegrity/Operational","Microsoft-Windows-AppLocker/EXE and DLL","Microsoft-Windows-AppLocker/MSI and Script","Microsoft-Windows-AppLocker/Packaged app-Deployment","Microsoft-Windows-AppLocker/Packaged app-Execution"; ID=$EventsToUse} -Oldest:$Oldest)
        }
    } else {
        if ($MaxEvents) {
            return (Get-WinEvent -ComputerName $RemoteMachine -FilterHashtable @{ Logname = "Microsoft-Windows-CodeIntegrity/Operational","Microsoft-Windows-AppLocker/EXE and DLL","Microsoft-Windows-AppLocker/MSI and Script","Microsoft-Windows-AppLocker/Packaged app-Deployment","Microsoft-Windows-AppLocker/Packaged app-Execution"; ID=$EventsToUse} -MaxEvents $MaxEvents -Oldest:$Oldest)
        } else {
            return (Get-WinEvent -ComputerName $RemoteMachine -FilterHashtable @{ Logname = "Microsoft-Windows-CodeIntegrity/Operational","Microsoft-Windows-AppLocker/EXE and DLL","Microsoft-Windows-AppLocker/MSI and Script","Microsoft-Windows-AppLocker/Packaged app-Deployment","Microsoft-Windows-AppLocker/Packaged app-Execution"; ID=$EventsToUse} -Oldest:$Oldest)
        }
    }
}

Export-ModuleMember -Function Get-MiscWDACEvents