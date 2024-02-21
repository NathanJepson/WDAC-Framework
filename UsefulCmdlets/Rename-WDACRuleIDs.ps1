function Update-WDACRulesIDs {
    <#
    .SYNOPSIS
    For rule IDs that have extraneous _0 and _1 concatenated on the end, shorten them if possible

    .DESCRIPTION
    For rule IDs with _0 and _1 at the end, a single passthrough is completed which checks whether the
    rule ID can be shortened without collisions -- then it is shortened. 

    This is done for EVERY rule for the designated policy.

    Author: Nathan Jepson
    License: MIT License
    #>

    [CmdletBinding()]
    Param (
        [string]$PolicyGUID,
        [string]$PolicyName
    )

    if (-not ($PolicyGUID -or $PolicyName)) {
        throw "Please provide a policy GUID or policy name."
    } elseif ($PolicyGUID -and $PolicyName) {
        throw "Please provide a policy GUID or policy name, but not both."
    }

    try {
        if ($PolicyName) {
            if (-not (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop)) {
                throw "There are no policies by this policy name: $PolicyName in the database."
            }
            $PolicyGUID = (Get-WDACPolicyGUIDGivenName -PolicyName $PolicyName).PolicyGUID
        } elseif ($PolicyGUID) {
            if (-not (Find-WDACPolicy -PolicyGUID $PolicyGUID -ErrorAction Stop)) {
                throw "Not a valid policy GUID (does not exist)."
            }
        }
    } catch {
        throw "Trouble accessing the policy designated (DB issues, or not a valid policy)."
    }

    if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
    } else {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    }

    $PolicyPath = (Get-FullPolicyPath -PolicyGUID $PolicyGUID -ErrorAction Stop)
    if (-not (Test-Path $PolicyPath)) {
        throw "$PolicyGUID was not found at path $PolicyPath"
    }
    $rules = Get-CIPolicy -FilePath $PolicyPath -ErrorAction Stop
    $Pattern1 = 'ID_ALLOW_[A-Z][_A-Z0-9]+'
    $Pattern2 = 'ID_DENY_[A-Z][_A-Z0-9]+'
    $Pattern3 = 'ID_SIGNER_[A-Z][_A-Z0-9]+'
    $Pattern4 = 'ID_FILEATTRIB_[A-Z][_A-Z0-9]+'

    $OldPolicyPath = $PolicyPath
    $RandomGUID = New-Guid
    $BackupPolicyLocation = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\$RandomGUID.xml")
    $GeneralSuccess = $false

    if ((-not $BackupPolicyLocation)) {
        throw "Cannot instantiate backup file path."
    }
    try {
        Copy-Item $OldPolicyPath -Destination $BackupPolicyLocation -Force -ErrorAction Stop
        $ruleIDs = @{}
        foreach ($rule in $rules) {
        #I'm putting this all into a map because I've run into issues with SecureBoot rule references before
            $ruleIDs += @{$rule.ID = $true}
        }
    
        foreach ($ruleMapEntry in $ruleIDs.GetEnumerator()) {
            $ruleID = $ruleMapEntry.Name
    
            if ( ($ruleID -match $Pattern1) -or ($ruleID -match $Pattern2) -or ($ruleID -match $Pattern3) -or ($ruleID -match $Pattern4)) {
                if (($ruleID.Substring($ruleID.Length-2,2) -eq "_0") -or ($ruleID.Substring($ruleID.Length-2,2) -eq "_1")) {
                    $decremented = $ruleID.Substring(0,$ruleID.Length-2) 
                    if (($decremented -match $Pattern1) -or ($decremented -match $Pattern2) -or ($decremented -match $Pattern3) -or ($decremented -match $Pattern4)) {
                    #If a decremented version of the rule still matches the previous regex
                        $swap_underscore = $null
                        if (($ruleID.Substring($ruleID.Length-2,2) -eq "_0")) {
                            $swap_underscore = $decremented + "_1"
                        } else {
                            $swap_underscore = $decremented + "_0"
                        }
                        $GoodToDecrement = $true
    
                        $FileContent = Get-Content -Path $OldPolicyPath -ErrorAction Stop

                        for ($i=0; $i -lt $FileContent.Count; $i++) {
                            if ( ($FileContent[$i].Contains("`"$swap_underscore`"")) -or ($FileContent[$i].Contains("`"$decremented`""))) {
                                $GoodToDecrement = $false
                                break
                            }
                        }

                        if ($GoodToDecrement) {
                            $NewContent = $FileContent.Replace("`"$ruleID`"","`"$decremented`"")
                            $NewContent | Set-Content -Path $OldPolicyPath -Force -ErrorAction Stop
                            $GeneralSuccess = $true
                        }
                    }
                }
            }
        }

        if ($GeneralSuccess) {
            Write-Host "Completed one pass for shortening rule IDs." -ForegroundColor Green
        }

        if (Test-Path $BackupPolicyLocation) {
            Remove-Item $BackupPolicyLocation -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Verbose ($_ | Format-List -Property * -Force | Out-String)

        if ($BackupPolicyLocation -and $OldPolicyPath) {
            if (Test-Path $BackupPolicyLocation) {
                try {
                    Copy-Item $BackupPolicyLocation -Destination $OldPolicyPath -Force -ErrorAction Stop
                } catch {
                    Write-Error "Failed to restore policy $PolicyGUID but it can be recovered at $BackupPolicyLocation"
                }
            }
        }

        throw $_
    }
}

function Rename-WDACRuleID {
    
}