function CommentPreserving {
    [CmdletBinding()]
    param (
        $IDsAndComments,
        $FilePath
    )

    $FileContent = Get-Content $FilePath -ErrorAction Stop
    $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-F0-9]+(?=")'
    $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-F0-9]+(?=")'
    $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-F0-9]+(?=")'
    $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-F0-9]+(?=")'
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

function Remove-UnderscoreDigits {
#This function removes the underscore digits at the end since we've already accounted for duplicates
    [CmdletBinding()]
    param (
        $FilePath
    )

    $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-F0-9]+(?=")'
    $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-F0-9]+(?=")'
    $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-F0-9]+(?=")'
    $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-F0-9]+(?=")'
    
    $FileContent = Get-Content -Path $FilePath -ErrorAction Stop

    for ($i=0; $i -lt $FileContent.Count; $i++) {
        if ( ($FileContent[$i] -match $Pattern1) -or ($FileContent[$i] -match $Pattern2) -or ($FileContent[$i] -match $Pattern3) -or ($FileContent[$i] -match $Pattern4)) {
            $FileContent[$i] = $FileContent[$i].replace($Matches[0],$Matches[0].Substring(0,$Matches[0].Length-2))
        }
    }

    $FileContent | Set-Content -Path $FilePath -Force -ErrorAction Stop
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
            $ID = $Entry.Key
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

function Merge-TrustedWDACRules {
    <#
    .SYNOPSIS
    For specified Policies only, this cmdlet will observe any entry in the database with a trust or block flag (with no staged flag), and will merge those rules into the designated AllowedPolicyID or BlockingPolicyID

    .DESCRIPTION
    For each instance of a potential rule with a trust or block flag in the database, a new [Microsoft.SecureBoot.UserConfig.Rule] is created which will
    eventually be merged with the correct policy using the Merge-CIPolicy cmdlet. ConfigCI is imported directly into your version of PowerShell,
    e.g., PowerShell 7 (rather than running in a PowerShell 5.1 container--which is potentially dangerous, since it is not approved for PowerShell 7 yet.)
    If a potential rule entry (for example, a row of the publishers table) has a COMMENT entry, this cmdlet will attempt to put an XML comment
    above where the rule is located in the .XML file. 
    For signers and publishers, a [Microsoft.SecureBoot.UserConfig.Rule] object is created using Get-CIPolicy with a temporary XML object containing the correct
    root or publisher name--since there is no other way that Microsoft allows you to create a [Microsoft.SecureBoot.UserConfig.Rule] using a custom root 
    (other than ingesting a certificate directly--which I don't want to do because many of the database entries are events which are pulled from remote devices and it'd
    be too much of a hassle to try and grab certificates from all those remote devices--especially if the app directories are not accessible or the files are deleted.)

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
    Merge-TrustedWDACRules -PolicyGUID "d800d7bc-7be6-45d6-8665-91d9d61c3530" -Level Publisher -Verbose

    .EXAMPLE
    Merge-TrustedWDACRules -GroupName Cashiers -Levels FilePublisher,Publisher,Hash
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
    #...(And I run into weird constrained language mode restrictions if I try and do that.)
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
                        $rule,$IDsAndComments = New-MicrosoftSecureBootLeafCertificateRule -RuleInfo $LeafCertRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "PcaCertificate" {
                    $PotentialPcaCertRules = Get-PotentialPcaCertificateRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PcaCertRule in $PotentialPcaCertRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootPcaCertificateRule -RuleInfo $PcaCertRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -ErrorAction Stop
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += 1
                        }
                    }
                }
                "Publisher" {
                    $PotentialPublisherRules = Get-PotentialPublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PublisherRule in $PotentialPublisherRules) {
                        $rule,$IDsAndComments = New-MicrosoftSecureBootPublisherRule -RuleInfo $PublisherRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -Connection $Connection -ErrorAction Stop
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

                $FullPolicyPath = (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop)
                $IDsAndComments = CommentPreserving -IDsAndComments $IDsAndComments -FilePath $FullPolicyPath -ErrorAction Stop
                Merge-CIPolicy -PolicyPaths $FullPolicyPath -Rules $RulesToMerge -OutputFilePath $TempFilePath -ErrorAction Stop
                #Since we've already checked for duplicate IDs, we can remove the _0 and _1 that Merge-CIPolicy puts at the end of each ID
                Remove-UnderscoreDigits -FilePath $TempFilePath -ErrorAction Stop
                Add-WDACRuleComments -IDsAndComments $IDsAndComments -FilePath $TempFilePath -ErrorAction Stop
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