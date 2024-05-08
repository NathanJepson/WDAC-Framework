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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part2.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part2.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools_Part2.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\WorkingPolicies-and-DB-IO.psm1")
}

function Add-LineBeforeSpecificLine {
    [CmdletBinding()]
    param (
        $Line,
        $LineNumber,
        $FilePath
    )

    if ($LineNumber -le 1) {
        throw "Cannot append line at this location."
    }

    $FileContent = Get-Content -Path $FilePath
    $result = @()
    for ($i=0; $i -lt $FileContent.Count; $i++) {
        $result += $FileContent[$i]
        if ($i -eq ($LineNumber - 2)) {
        #The reason we subtract 2 here instead of 1 is because the count starts at 0 while the line numbers start at 1
            $result += $Line
        }
    }

    $result | Set-Content -Path $FilePath -Force
}

function Add-WDACRuleComments {
    [CmdletBinding()]
    param (
        $IDsAndComments,
        $FilePath
    )

    foreach ($Entry in $IDsAndComments.GetEnumerator()) {
        if (($Entry.Value) -and ($Entry.Value -ne $true)) {
            $ID = "`"" + $Entry.Key + "`""
            $Comment = ("<!--" + $Entry.Value + "-->")
            $IDInstances = Select-String -Path $FilePath -Pattern $ID

            for ($i=0; $i -lt $IDInstances.Count; $i++) {
                #The reason we grab a second time for each instance is that line numbers are all changed once a line is appended to a location
                $IDInstances2 = Select-String -Path $FilePath -Pattern $ID
                foreach ($IDInstance in $IDInstances2) {
                    if (($IDInstances[$i]).Line -eq $IDInstance.Line) {
                        if ( ($IDInstance.LineNumber) -gt 1) {
                            if (-not (((Get-Content $FilePath -TotalCount ($IDInstance.LineNumber -1))[-1] -match "<!--") -or ((Get-Content $FilePath -TotalCount ($IDInstance.LineNumber -1))[-1] -match "-->"))) {
                            #If there is not already a comment above the line where the ID appears
                                Add-LineBeforeSpecificLine -Line $Comment -LineNumber $IDInstance.LineNumber -FilePath $FilePath -ErrorAction Stop
                                break;
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }
}

function Remove-UnderscoreDigits {
    #This function removes the underscore digits at the end since we've already accounted for duplicates
    [CmdletBinding()]
    param (
        $FilePath
    )

    $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]+(?=")'
    $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]+(?=")'
    $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]+(?=")'
    $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]+(?=")'
    
    $FileContent = Get-Content -Path $FilePath -ErrorAction Stop

    for ($i=0; $i -lt $FileContent.Count; $i++) {
        if ( ($FileContent[$i] -match $Pattern1) -or ($FileContent[$i] -match $Pattern2) -or ($FileContent[$i] -match $Pattern3) -or ($FileContent[$i] -match $Pattern4)) {
            $FileContent[$i] = $FileContent[$i].replace($Matches[0],$Matches[0].Substring(0,$Matches[0].Length-2))
        }
    }

    $FileContent | Set-Content -Path $FilePath -Force -ErrorAction Stop
}

function Remove-WDACRule {
    <#
    .SYNOPSIS
    Remove a rule by ID that is present in a WDAC policy

    .DESCRIPTION
    By specifying a rule by ID--which rule is in the policy designated by the provided policy GUID--the file for this policy pointed to by 
    Get-FullPolicyPath--will be edited so that that this rule is removed.
    While currently there is a Remove-CIPolicyRule documented on Microsoft's website, they say not to use it, and it's unclear if it saves comments (hence
    why I made this cmdlet.)

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER RuleID
    The ID of the rule you want to remove, i.e., ID_DENY_WSL or ID_FILEATTRIB_SANDBOX

    .PARAMETER PolicyGUID
    GUID of the policy you would like to remove the rule(s) from

    .PARAMETER DontIncrementVersion
    Don't increment the version number of the policy after removing the rule(s)

    .EXAMPLE
    Remove-WDACRule -RuleID "ID_DENY_WSL" -PolicyGUID "fd3ea102-c502-4875-9d5c-42f92f9944da"

    .EXAMPLE
    Remove-WDACRule -RuleID "ID_DENY_WSL","ID_FILEATTRIB_SANDBOX" -PolicyGUID "fd3ea102-c502-4875-9d5c-42f92f9944da" -DontIncrementVersion
    #>

    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string[]]$RuleID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$DontIncrementVersion
    )

    $TempPolicyPath = $null
    $BackupOldPolicy = $null
    $Connection = $null
    $Transaction = $null
    $HVCIOption = $null

    try {
        if ($ThisIsASignedModule) {
            Write-Verbose "The current file is in the SignedModules folder."
        }

        $IDsAndComments = @{}
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        $HVCIOption = Get-HVCIPolicySetting -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $FullPolicyPath = (Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)
        $TempPolicyPath = Get-WDACHollowPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $BackupOldPolicy = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
        Copy-Item $FullPolicyPath -Destination $BackupOldPolicy -Force -ErrorAction Stop
        $CurrentPolicyVersion = Get-WDACPolicyVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        $RemoveRuleTask = {
        #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
            $InputArray = @($input)
            $FullPolicyPath = $InputArray[0]
            $TempPolicyPath = $InputArray[1]
            $IDsAndComments = $InputArray[2]
            $RuleID = $InputArray[3]
        
            function CommentPreserving {
                [CmdletBinding()]
                param (
                    $IDsAndComments,
                    $FilePath
                )
            
                $FileContent = Get-Content $FilePath -ErrorAction Stop
                $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]+(?=")'
                $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]+(?=")'
                $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]+(?=")'
                $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]+(?=")'
                $CommentPattern = "(?<=<!--).+(?=-->)"
            
                for ($i=0; $i -lt $FileContent.Count; $i++) {
                    if ( (($FileContent[$i] -match $Pattern1) -or ($FileContent[$i] -match $Pattern2) -or ($FileContent[$i] -match $Pattern3) -or ($FileContent[$i] -match $Pattern4)) -and ($i -gt 0)) {
                        $TempID = $Matches[0]
                        if ($IDsAndComments[$TempID] -eq $true -and ($FileContent[$i -1] -match $CommentPattern)) {
                            $IDsAndComments[$TempID] = $Matches[0]
                        }
                    }
                }
            
                return $IDsAndComments
            }
            
            $RuleNotPresent = $true

            try {
                $RulesToMerge = @()
                $CurrentPolicyRules = Get-CIPolicy -FilePath $FullPolicyPath -ErrorAction Stop
                foreach ($currentRule in $CurrentPolicyRules) {
                    if (-not ($IDsAndComments[$currentRule.Id])) {
                        $IDsAndComments = $IDsAndComments + @{$currentRule.Id = $true}
                    }
                }
                
                $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $FullPolicyPath -ErrorAction Stop

                foreach ($currentRule in $CurrentPolicyRules) {
                    if (-not ($RuleID -contains $currentRule.Id)) {
                        $RulesToMerge += $currentRule
                    } else {
                        $RuleNotPresent = $false
                    }
                }

                if ($RuleNotPresent) {
                    return "RuleNotPresent"
                }
                
                Merge-CIPolicy -PolicyPaths $TempPolicyPath -Rules $RulesToMerge -OutputFilePath $FullPolicyPath -ErrorAction Stop | Out-Null
            } catch {
                Write-Warning $_
                return $null
            }
           
            return $IDsAndComments

        }

        $IDsAndComments = $FullPolicyPath,$TempPolicyPath,$IDsAndComments,$RuleID | PowerShell $RemoveRuleTask
        
        if ($null -eq $IDsAndComments) {
            throw "Unable to remove rule, problems with merging other rules."
        } elseif ($IDsAndComments -eq "RuleNotPresent") {
            throw "Designated rule(s) not present in this policy."
        }

        Remove-UnderscoreDigits -FilePath $FullPolicyPath -ErrorAction Stop
        Add-WDACRuleComments -IDsAndComments $IDsAndComments -FilePath $FullPolicyPath -ErrorAction Stop
        
        if (-not $DontIncrementVersion) {
            New-WDACPolicyVersionIncrementOne -PolicyGUID $PolicyGUID -CurrentVersion $CurrentPolicyVersion -Connection $Connection -ErrorAction Stop
        } else {
            Set-XMLPolicyVersion -PolicyGUID $PolicyGUID -Version $CurrentPolicyVersion -Connection $Connection -ErrorAction Stop
        }

        if (Test-WDACPolicySigned -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) {
            if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $PolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Signed -Connection $Connection -ErrorAction Stop)) {
                throw "Could not set LastSignedVersion attribute on Policy $PolicyGUID"
            }
        } else {
            if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $PolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Unsigned -Connection $Connection -ErrorAction Stop)) {
                throw "Could not set LastUnsignedVersion attribute on Policy $PolicyGUID"
            }
        }

        try {
            if ($HVCIOption) {
                if ( (Get-HVCIPolicySetting -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -ne $HVCIOption) {
                    Set-HVCIPolicySetting -PolicyGUID $PolicyGUID -HVCIOption $HVCIOption -Connection $Connection -ErrorAction Stop
                }
            }
        } catch {
            Write-Warning $_
        }
        

        $Transaction.Commit()
        $Connection.Close()
        Write-Host "Successfully removed rule(s)."

        if (Test-Path $TempPolicyPath) {
            Remove-Item -Path $TempPolicyPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $BackupOldPolicy) {
            Remove-Item -Path $BackupOldPolicy -Force -ErrorAction SilentlyContinue
        }
    } catch {
        if ($Transaction -and $Connection) {
            if ($Connection.AutoCommit -eq $false) {
                $Transaction.Rollback()
            }
        }
        if ($Connection) {
            $Connection.Close()
        }
        if ($TempPolicyPath) {
            if (Test-Path $TempPolicyPath) {
                Remove-Item -Path $TempPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
        if ($BackupOldPolicy) {
            if ( (Test-Path $BackupOldPolicy) -and $FullPolicyPath) {
                Copy-Item -Path $BackupOldPolicy -Destination $FullPolicyPath -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $BackupOldPolicy -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Verbose ($_ | Format-List -Property * | Out-String)
        throw $_
    }
}

Export-ModuleMember -Function Remove-WDACRule
