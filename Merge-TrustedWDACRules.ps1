function New-MicrosoftSecureBootHashRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )

    #TODO: MSIorScript check
}

function New-MicrosoftSecureBootFilePathRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
    #TODO: FilePath rules not yet implemented
}

function New-MicrosoftSecureBootFileNameRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootLeafCertificateRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootPcaCertificateRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootPublisherRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootFilePublisherRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

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
        [string[]]$PolicyID
    )

    $Levels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
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
            $Transaction = $Connection.BeginTransaction()
            $MostRecentPolicy = $Policy
            $BackupOldPolicy = $null

            switch ($Levels) {
                "Hash" {
                    $PotentialHashRules_PE = Get-PotentialHashRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    $PotentialHashRules_MSIorScript = Get-PotentialHashRules -MSIorScript -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop

                    foreach ($HashRulePE in $PotentialHashRules_PE) {
                        $rule = New-MicrosoftSecureBootHashRule -RuleInfo $HashRulePE -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                    foreach ($HashRuleMSI in $PotentialHashRules_MSIorScript) {
                        $rule = New-MicrosoftSecureBootHashRule -RuleInfo $HashRuleMSI -ErrorAction Stop
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
                        $rule = New-MicrosoftSecureBootFileNameRule -RuleInfo $FileNameRule -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "LeafCertificate" {
                    $PotentialLeafCertRules = Get-PotentialLeafCertificateRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($LeafCertRule in $PotentialLeafCertRules) {
                        $rule = New-MicrosoftSecureBootLeafCertificateRule -RuleInfo $LeafCertRule -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "PcaCertificate" {
                    $PotentialPcaCertRules = Get-PotentialPcaCertificateRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PcaCertRule in $PotentialPcaCertRules) {
                        $rule = New-MicrosoftSecureBootPcaCertificateRule -RuleInfo $PcaCertRule -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "Publisher" {
                    $PotentialPublisherRules = Get-PotentialPublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PublisherRule in $PotentialPublisherRules) {
                        $rule = New-MicrosoftSecureBootPublisherRule -RuleInfo $PublisherRule -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "FilePublisher" {
                   $PotentialFilePublisherRules = Get-PotentialFilePublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($FilePublisherRule in $PotentialFilePublisherRules) {
                        $rule = New-MicrosoftSecureBootFilePublisherRule -RuleInfo $FilePublisherRule -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
            }

            if ($RulesAdded -ge 1) {

                $TempFilePath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + (New-Guid + ".xml")))

                $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction SilentlyContinue)."WorkingPoliciesDirectory"."Type"
                if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
                #This is to recover the old version of the file is an exception happens
                    $BackupOldPolicy = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + (New-Guid + ".xml")))
                    Copy-Item (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction SilentlyContinue) -Destination $BackupOldPolicy -ErrorAction SilentlyContinue
                }

                Merge-CIPolicy -PolicyPaths (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop) -Rules $RulesToMerge -OutputFilePath $TempFilePath -ErrorAction Stop
                Receive-FileAsPolicy -FilePath $TempFilePath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop

                # $AddRulesTask = PowerShell {
                #     [CmdletBinding()]
                #     Param(
                #         $RuleList
                #     )
                # } -args $RuleToMerge

                $PolicyVersion = (Get-PolicyVersionNumber -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop).PolicyVersion
                if ($PolicyVersion) {
                    $NewVersionNum = Set-IncrementVersionNumber -VersionNumber $PolicyVersion
                    Set-WDACPolicyVersion -PolicyGUID $Policy -Version $NewVersionNum -Connection $Connection -ErrorAction Stop
                    Set-XMLPolicyVersion -PolicyGUID $Policy -Version $NewVersionNum -Connection $Connection -ErrorAction Stop
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
                                Receive-FileAsPolicy -FilePath $BackupOldPolicy -PolicyGUID $Policy -ErrorAction Stop
                            } catch {
                                try {
                                    Copy-Item $BackupOldPolicy -Destination (Get-FullPolicyPath -PolicyGUID $Policy -ErrorAction Stop) -Force -ErrorAction Stop
                                } catch {
                                    Write-Error "Unable to re-write old policy XML for policy $Policy but it can be recovered at $BackupOldPolicy"
                                }
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
                    Receive-FileAsPolicy -FilePath $BackupOldPolicy -PolicyGUID $Policy -ErrorAction Stop
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