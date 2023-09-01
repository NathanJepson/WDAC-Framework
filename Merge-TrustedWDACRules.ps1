function Merge-TrustedWDACRules {
    <#
    .SYNOPSIS
    For specified Policies only, this cmdlet will observe any entry in the database with a trust or block flag (with no staged flag), and will merge those rules into the designated AllowedPolicyID or BlockingPolicyID

    .DESCRIPTION
    TODO

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER GroupName
    When GroupName is specified, every policy assigned to that group will merge ready-to-stage rules which have been trusted (or blocked)

    .PARAMETER PolicyName
    The name of the policy or policies -- when specified, every potential rule in the database with a trust or block flag with AllowedPolicyID or BlockingPolicyID will be merged

    .PARAMETER PolicyGUID
    The GUID of the policy or policies -- when specified, every potential rule in the database with a trust or block flag with AllowedPolicyID or BlockingPolicyID will be merged

    .PARAMETER PolicyID
    The ID (not the GUID!) of the policy or policies -- when specified, every potential rule in the database with a trust or block flag with AllowedPolicyID or BlockingPolicyID will be merged

    .PARAMETER Levels
    When Levels are specified, only rules from the specified levels will be merged to policies

    .EXAMPLE
    TODO

    .EXAMPLE
    TODO
    #>

    [CmdletBinding()]
    param (
        [string]$GroupName,
        [string[]]$PolicyName,
        [string[]]$PolicyGUID,
        [string[]]$PolicyID,
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        [Alias("Level")]
        [string[]]$Levels
    )

    #The only reason that -SkipEditionCheck is used here is that I'm reasonably sure that using these commands won't break in PowerShell 7, but I could be wrong!
    #...Either way, this is really the only way that this cmdlet works. I could wrap everything (EVERYTHING) in a PowerShell 5.1 block, but I don't think I need to.
    Import-Module -SkipEditionCheck -Name "ConfigCI"

    if (-not $Levels) {
        $Levels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    }
    $Policies = @()
    $MostRecentPolicy = $null
    if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
        Write-Verbose "The current file is in the SignedModules folder."
    } else {
        $PSModuleRoot = $PSScriptRoot
    }

    try {
        if ($GroupName) {
            $PolicyAssignments = Get-WDACPolicyAssignments -GroupName $GroupName -ErrorAction Stop
            foreach ($Assignment in $PolicyAssignments) {
                $Policies += $Assignment.PolicyGUID
            }
        }
    
        if ($PolicyName) {
            foreach ($Name in $PolicyName) {
                if (-not (Find-WDACPolicyByName -PolicyName $Name -ErrorAction Stop)) {
                    throw "No policy exists with name $Name ."
                } else {
                    $Policies += ((Get-WDACPolicyByName -PolicyName $Name -ErrorAction Stop).PolicyGUID)
                }
            }
        }

        if ($PolicyGUID) {
            foreach ($thisID in $PolicyGUID) {
                if (-not (Find-WDACPolicy -PolicyGUID $thisID -ErrorAction Stop)) {
                    throw "No policy exists with GUID $thisID ."
                } else {
                    $Policies += $thisID
                }
            }
        }

        if ($PolicyID) {
            foreach ($thisID in $PolicyID) {
                if (-not (Find-WDACPolicyByID -PolicyID $thisID -ErrorAction Stop)) {
                    throw "No policy exists with ID $thisID ."
                } else {
                    $policiesByID = Get-WDACPoliciesById -PolicyID $thisID -ErrorAction Stop
                    foreach ($thisPolicyByID in $policiesByID) {
                        $Policies += ($thisPolicyByID.PolicyGUID)
                    }
                }
            }
        }

        if ($Policies.Count -lt 1) {
            throw "No policies GUIDs provided to merge trusted WDAC rules into."
        }
    
        $Connection = New-SQLiteConnection -ErrorAction Stop
        
        foreach ($Policy in $Policies) {
            $RulesAdded = 0
            $RulesToMerge = @()
            $IDsAndComments = @{}
            $Transaction = $Connection.BeginTransaction()
            $MostRecentPolicy = $Policy
            $BackupOldPolicy = $null
            $CurrentPolicyRules = Get-CIPolicy -FilePath (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop) -ErrorAction Stop
            foreach ($currentRule in $CurrentPolicyRules) {
                $IDsAndComments.Add($currentRule.Id,$true)
            }

            switch ($Levels) {
                "Hash" {
                    $PotentialHashRules_PE = Get-PotentialHashRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    $PotentialHashRules_MSIorScript = Get-PotentialHashRules -MSIorScript -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop

                    foreach ($HashRulePE in $PotentialHashRules_PE) {
                        
                        $rule,$IDsAndComments = New-MicrosoftSecureBootHashRule -RuleInfo $HashRulePE -RuleMap $IDsAndComments -ErrorAction Stop

                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                    foreach ($HashRuleMSI in $PotentialHashRules_MSIorScript) {
                        $rule = New-MicrosoftSecureBootHashRule -RuleInfo $HashRuleMSI -MSIorScript -RuleMap $IDsAndComments -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "FilePath" {
                    #TODO
                    Write-Verbose "FilePath rules have not yet been implemented."
                }
                "FileName" {
                    $PotentialFileNameRules = Get-PotentialFileNameRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($FileNameRule in $PotentialFileNameRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootFileNameRule -RuleInfo $FileNameRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "LeafCertificate" {
                    $PotentialLeafCertRules = Get-PotentialLeafCertificateRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($LeafCertRule in $PotentialLeafCertRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootLeafCertificateRule -RuleInfo $LeafCertRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "PcaCertificate" {
                    $PotentialPcaCertRules = Get-PotentialPcaCertificateRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PcaCertRule in $PotentialPcaCertRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootPcaCertificateRule -RuleInfo $PcaCertRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "Publisher" {
                    $PotentialPublisherRules = Get-PotentialPublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PublisherRule in $PotentialPublisherRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootPublisherRule -RuleInfo $PublisherRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "FilePublisher" {
                   $PotentialFilePublisherRules = Get-PotentialFilePublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($FilePublisherRule in $PotentialFilePublisherRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootFilePublisherRule -RuleInfo $FilePublisherRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
            }

            if ($RulesAdded -ge 1) {

                $TempFilePath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))

                $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction SilentlyContinue)."WorkingPoliciesDirectory"."Type"
                if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
                #This is to recover the old version of the file is an exception happens
                    $BackupOldPolicy = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
                    Copy-Item (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction SilentlyContinue) -Destination $BackupOldPolicy -ErrorAction SilentlyContinue
                }

                Merge-CIPolicy -PolicyPaths (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop) -Rules $RulesToMerge -OutputFilePath $TempFilePath -ErrorAction Stop
                Receive-FileAsPolicy -FilePath $TempFilePath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop

                $PolicyVersion = (Get-PolicyVersionNumber -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop).PolicyVersion
                $OldPolicyPath = (Get-FullPolicyPath -PolicyGUID $Policy -ErrorAction Stop)
                if ($PolicyVersion) {
                    New-WDACPolicyVersionIncrementOne -PolicyGUID $Policy -CurrentVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
                    $Transaction.Commit()
                    Write-Host "Successfully committed changes to Policy $Policy" -ForegroundColor Green
                    if ($TempFilePath) {
                        if (Test-Path $TempFilePath) {
                            Remove-Item -Path $TempFilePath -ErrorAction SilentlyContinue
                        }
                    }
                } else {
                    $Transaction.Rollback()
                    if ($BackupOldPolicy) {
                        if (Test-Path $BackupOldPolicy) {
                            try {
                                Copy-Item $BackupOldPolicy -Destination $OldPolicyPath -Force -ErrorAction Stop
                            } catch {
                                Write-Error "Unable to re-write old policy XML for policy $Policy but it can be recovered at $BackupOldPolicy"
                            }
                        }
                    }
                    throw "Trouble retrieving version number using Get-PolicyVersionNumber"
                }
            } else {
                $Transaction.Rollback()
            }
        }

    } catch {
        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }
        
        if ($MostRecentPolicy -and $BackupOldPolicy) {
            if (Test-Path $BackupOldPolicy) {
                try {
                    Receive-FileAsPolicy -FilePath $BackupOldPolicy -PolicyGUID $MostRecentPolicy -ErrorAction Stop
                    Remove-Item $BackupOldPolicy -ErrorAction SilentlyContinue
                } catch {
                    Write-Error "Unable to re-write old policy XML for policy $MostRecentPolicy but it can be recovered at $BackupOldPolicy"
                }
            }
        }

        if ($TempFilePath) {
            if (Test-Path $TempFilePath) {
                Remove-Item -Path $TempFilePath -ErrorAction SilentlyContinue
            }
        }

        Write-Verbose ($_ | Format-List * -Force | Out-String)
        throw $_
    }
}