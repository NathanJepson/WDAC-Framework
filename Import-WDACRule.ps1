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

function Import-WDACRule {
    <#
    .SYNOPSIS
    Import WDAC rule(s)--by ID--from a reference XML file or policy known by the database, and merge to a destination policy.

    .DESCRIPTION
    Specify WDAC rule(s) by ID which exist in a reference policy, then merge them into a destination policy (version number
    of the destination policy will increment unless you specify "DontIncrementVersion")

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER RuleID
    The ID of the rule you want to remove, i.e., ID_DENY_WSL or ID_FILEATTRIB_SANDBOX

    .PARAMETER DestinationPolicyGUID
    GUID of the policy you would like to remove the rule(s) from

    .PARAMETER DontIncrementVersion
    Don't increment the version number of the policy after importing the rule(s)

    .PARAMETER ReferenceFile
    The .XML file you want to look in for the referenced rules.

    .PARAMETER ReferencePolicyGUID
    The policy designated by the GUID which you want to look in for the referenced rules.

    .EXAMPLE
    Import-WDACRule -RuleID "ID_DENY_WSL" -ReferenceFile "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -DestinationPolicy "fd3ea102-c502-4875-9d5c-42f92f9944da"

    .EXAMPLE
    Import-WDACRule -RuleID "ID_DENY_WSL","ID_FILEATTRIB_SANDBOX" -ReferencePolicyGUID "56da09ef-9e25-45af-be42-41cfd33645ae" -DestinationPolicy "fd3ea102-c502-4875-9d5c-42f92f9944da" -DontIncrementVersion
    #>

    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string[]]$RuleID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("DestinationPolicy")]
        [string]$DestinationPolicyGUID,
        [switch]$DontIncrementVersion,
        [ValidatePattern('\.xml$')]
        [ValidateScript({Test-Path $_}, ErrorMessage = "Cannot find the the provided ReferenceFile path.")]
        [ValidateNotNullOrEmpty()]
        [Alias("ReferenceXML")]
        [string]$ReferenceFile,
        [string]$ReferencePolicyGUID
    )

    $TempPolicyPath = $null
    $BackupOldPolicy = $null
    $Connection = $null
    $Transaction = $null
    $HVCIOption = $null

    if ($ReferenceFile -and $ReferencePolicyGUID) {
        throw "Must provide either a reference file OR a reference policy GUID (not both)."
    }

    if ((-not $ReferenceFile) -and (-not $ReferencePolicyGUID)) {
        throw "You must provide a reference policy."
    }

    if ($DestinationPolicyGUID -eq $ReferencePolicyGUID) {
        throw "Destination policy GUID cannot equal reference policy GUID."
    }

    if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
        Write-Verbose "The current file is in the SignedModules folder."
    } else {
        $PSModuleRoot = $PSScriptRoot
    }

    try {
        $IDsAndComments = @{}
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        $HVCIOption = Get-HVCIPolicySetting -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop

        if ($ReferencePolicyGUID) {
            $ReferenceFile = (Get-FullPolicyPath -PolicyGUID $ReferencePolicyGUID -Connection $Connection -ErrorAction Stop)
        }

        $FullPolicyPath = (Get-FullPolicyPath -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop)
        $TempPolicyPath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
        $BackupOldPolicy = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
        Copy-Item $FullPolicyPath -Destination $BackupOldPolicy -Force -ErrorAction Stop
        $CurrentPolicyVersion = Get-WDACPolicyVersion -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop

        $ImportRuleTask = {
        #This needs to be wrapped in a PowerShell 5.1 block because some functionallity of ConfigCI isn't supported in PowerShell Core :(
            $InputArray = @($input)
            $FullPolicyPath = $InputArray[0]
            $TempPolicyPath = $InputArray[1]
            $IDsAndComments = $InputArray[2]
            $RuleID = $InputArray[3]
            $ReferenceFile = $InputArray[4]

            $result = @{}
            $referenceRuleMap = @{}
            $currentPolicyRuleMap = @{}

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

            try {
                $RulesToMerge = @()
                $ReferencePolicyRules = Get-CIPolicy -FilePath $ReferenceFile -ErrorAction Stop
                $CurrentPolicyRules = Get-CIPolicy -FilePath $FullPolicyPath -ErrorAction Stop

                foreach ($currentRule in $ReferencePolicyRules) {
                    if (($RuleID -contains $currentRule.Id)) {
                        $RulesToMerge += $currentRule
                    }
                }

                if ($RulesToMerge.Count -ne $RuleID.Count) {
                    return "RuleNotPresent"
                }
                
                Merge-CIPolicy -PolicyPaths $FullPolicyPath -Rules $RulesToMerge -OutputFilePath $TempPolicyPath -ErrorAction Stop | Out-Null
                #Note: Underscores are NOT removed from the rules after a merge, unlike other cmdlets!

                #The reason we re-set the arrays of rules here is there is something mega weird going on with the IDs after the rules are merged
                #even when you account for _0 and _1 that are appended at the end. Probably something with references, who knows.
                $ReferencePolicyRules = Get-CIPolicy -FilePath $ReferenceFile -ErrorAction Stop
                $CurrentPolicyRules = Get-CIPolicy -FilePath $FullPolicyPath -ErrorAction Stop
                
                foreach ($currentRule in $CurrentPolicyRules) {
                    if (-not ($currentPolicyRuleMap[$currentRule.Id])) {
                        $currentPolicyRuleMap = $currentPolicyRuleMap + @{$currentRule.Id = $true}
                    }
                }
                
                $currentPolicyRuleMap = CommentPreserving -IDsAndComments $currentPolicyRuleMap -FilePath $FullPolicyPath -ErrorAction Stop
                
                foreach ($currentRule in $ReferencePolicyRules) {
                    if (-not ($referenceRuleMap[$currentRule.Id])) {
                        $referenceRuleMap = $referenceRuleMap + @{$currentRule.Id = $true}
                    }
                }

                $referenceRuleMap = CommentPreserving -IDsAndComments $referenceRuleMap -FilePath $ReferenceFile -ErrorAction Stop

                foreach ($currentRuleEntry in $currentPolicyRuleMap.GetEnumerator()) {
                    $result = $result + @{"$($currentRuleEntry.Name)_0" = $currentRuleEntry.Value}
                }

                foreach ($referenceRuleEntry in $referenceRuleMap.GetEnumerator()) {
                    $result = $result + @{"$($referenceRuleEntry.Name)_1" = $referenceRuleEntry.Value}
                }

            } catch {
                Write-Warning $_
                return $null
            }
           
            return $result
        }

        $IDsAndComments = $FullPolicyPath,$TempPolicyPath,$IDsAndComments,$RuleID,$ReferenceFile | PowerShell $ImportRuleTask
        
        if ($null -eq $IDsAndComments) {
            throw "Unable to remove rule, problems with merging other rules."
        } elseif ($IDsAndComments -eq "RuleNotPresent") {
            throw "Some designated rule(s) not present in this policy."
        }

        Add-WDACRuleComments -IDsAndComments $IDsAndComments -FilePath $TempPolicyPath -ErrorAction Stop
        Receive-FileAsPolicy -FilePath $TempPolicyPath -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop
        
        if (-not $DontIncrementVersion) {
            New-WDACPolicyVersionIncrementOne -PolicyGUID $DestinationPolicyGUID -CurrentVersion $CurrentPolicyVersion -Connection $Connection -ErrorAction Stop
        } else {
            Set-XMLPolicyVersion -PolicyGUID $DestinationPolicyGUID -Version $CurrentPolicyVersion -Connection $Connection -ErrorAction Stop
        }

        try {
            if ($HVCIOption) {
                if ( (Get-HVCIPolicySetting -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop) -ne $HVCIOption) {
                    Set-HVCIPolicySetting -PolicyGUID $DestinationPolicyGUID -HVCIOption $HVCIOption -Connection $Connection -ErrorAction Stop
                }
            }
        } catch {
            Write-Warning $_
        }

        if (Test-WDACPolicySigned -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop) {
            if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $DestinationPolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Signed -Connection $Connection -ErrorAction Stop)) {
                throw "Could not set LastSignedVersion attribute on Policy $DestinationPolicyGUID"
            }
        } else {
            if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $DestinationPolicyGUID -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $DestinationPolicyGUID -Connection $Connection -ErrorAction Stop).PolicyVersion) -Unsigned -Connection $Connection -ErrorAction Stop)) {
                throw "Could not set LastUnsignedVersion attribute on Policy $DestinationPolicyGUID"
            }
        }

        $Transaction.Commit()
        $Connection.Close()
        Write-Host "Successfully merged rule(s)." -ForegroundColor Green

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