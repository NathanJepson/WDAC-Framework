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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Code-Signing-Tools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Code-Signing-Tools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\Code-Signing-Tools.psm1")
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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\Microsoft-SecureBoot-UserConfig-RuleManip.psm1")
}


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

function Add-WDACRuleCommentsv2 {
    #This function adds the comments associated with specific rule IDs back
        [CmdletBinding()]
        param (
            $IDsAndComments,
            $FilePath
        )
    
        $FileContent = Get-Content -Path $FilePath
        $ContentAndLineNumbers = @()
        foreach ($entry in $IDsAndComments.GetEnumerator()) {
            if (($Entry.Value) -and ($Entry.Value -ne $true)) {
                $ID = "`"" + $Entry.Key + "`""
                $Comment = ("<!--" + $Entry.Value + "-->")
                $IDInstances = Select-String -Path $FilePath -Pattern $ID
                foreach ($Instance in $IDInstances) {
                    $lineNumber = $Instance.LineNumber
                    if (-not (($FileContent[$lineNumber-2] -match "<!--") -or ($FileContent[$lineNumber-2] -match "-->"))) {
                        $ContentAndLineNumbers += @{ LineNumber = $lineNumber; Comment = $Comment}
                    }
                }
            }
        }
    
        $ContentAndLineNumbers = $ContentAndLineNumbers | Sort-Object -Property LineNumber -Descending
    
        foreach ($entry in $ContentAndLineNumbers) {
            $lineNumber = $entry.LineNumber
            $comment = $entry.Comment
    
            $FileContent = $FileContent[0..($lineNumber - 2)] + $comment + $FileContent[($lineNumber - 1)..($FileContent.Length - 1)]
        }
    
        $FileContent | Set-Content -Path $FilePath -Force
}

function Get-YesOrNoPrompt {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt
    )

    Write-Host ($Prompt + " (Y/N): ") -NoNewline
    while ($true) {
        $InputString = Read-Host
        if ($InputString.ToLower() -eq "y") {
            return $true
        } elseif ($InputString.ToLower() -eq "n") {
            return $false
        } else {
            Write-Host "Not a valid option. Please supply y or n."
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

    .PARAMETER PreserveBackup
    When this is set, it will keep a backup of the previous version of the policy before your rules were merged into it.

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
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName","Certificate")]
        [Alias("Level")]
        [string[]]$Levels,
        [Alias("KeepBackup","RetainBackup","NoOverwrite")]
        [switch]$PreserveBackup
    )

    #The only reason that -SkipEditionCheck is used here is that I'm reasonably sure that using these commands won't break in PowerShell 7, but I could be wrong!
    #...Either way, this is really the only way that this cmdlet works. I could wrap everything (EVERYTHING) in a PowerShell 5.1 block, but I don't think I need to.
    #...(And I run into weird constrained language mode restrictions if I try and do that.)
    Import-Module -SkipEditionCheck -Name "ConfigCI" -Verbose:$false

    if (-not $Levels) {
        $Levels = @("Hash","FilePath","FileName","Certificate","Publisher","FilePublisher")
    } elseif (($Levels -contains "LeafCertificate") -or ($Levels -contains "PcaCertificate")) {
        if (Get-YesOrNoPrompt -Prompt "In this cmdlet, ALL certificate rules are merged if PcaCertificate or LeafCertificate is provided. Is this okay?") {
            $Levels = $Levels | Where-Object {$_ -ne "LeafCertificate"}
            $Levels = $Levels | Where-Object {$_ -ne "PcaCertificate"}
            if (-not ($Levels -contains "Certificate")) {
                $Levels += "Certificate"
            }
        } else {
            return
        }
    }

    $Policies = @()

    $MostRecentPolicy = $null
    $TempFilePath = $null
    $HVCIOption = $null
    $Connection = $null
    $Transaction = $null
    $BackupOldPolicy = $null

    try {
        if ($ThisIsASignedModule) {
            Write-Verbose "The current file is in the SignedModules folder."
        }

        if ($GroupName) {
            $PolicyAssignments = Get-WDACPolicyAssignments -GroupName $GroupName -ErrorAction Stop
            foreach ($Assignment in $PolicyAssignments) {
                $Policies += $Assignment.PolicyGUID
            }
        }
    
        if ($PolicyName) {
            foreach ($Name in $PolicyName) {
                if (-not (Find-WDACPolicyByName -PolicyName $Name -ErrorAction Stop)) {
                    throw "No policy exists with name $Name"
                } else {
                    $Policies += ((Get-WDACPolicyByName -PolicyName $Name -ErrorAction Stop).PolicyGUID)
                }
            }
        }

        if ($PolicyGUID) {
            foreach ($thisID in $PolicyGUID) {
                if (-not (Find-WDACPolicy -PolicyGUID $thisID -ErrorAction Stop)) {
                    throw "No policy exists with GUID $thisID"
                } else {
                    $Policies += $thisID
                }
            }
        }

        if ($PolicyID) {
            foreach ($thisID in $PolicyID) {
                if (-not (Find-WDACPolicyByID -PolicyID $thisID -ErrorAction Stop)) {
                    throw "No policy exists with ID $thisID"
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
            $HVCIOption = Get-HVCIPolicySetting -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
            $CurrentPolicyRules = Get-CIPolicy -FilePath (Get-FullPolicyPath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop) -ErrorAction Stop
            foreach ($currentRule in $CurrentPolicyRules) {
                if (-not ($IDsAndComments[$currentRule.Id])) {
                #The only reason this check is necessary, is rules with a certain ID are duplicated based on if they are used for UserMode or Kernel mode
                #...Which then causes an error if you try to add that ID a second time
                    $IDsAndComments.Add($currentRule.Id,$true)
                }
            }

            switch ($Levels) {
                "Hash" {
                    $PotentialHashRules_PE = Get-PotentialHashRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    $PotentialHashRules_MSIorScript = Get-PotentialHashRules -MSIorScript -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop

                    foreach ($HashRulePE in $PotentialHashRules_PE) {
                        if ( ($HashRulePE.Blocked -eq $true) -and (($HashRulePE.TrustedDriver -eq $true) -or ($HashRulePE.TrustedUserMode -eq $true))) {
                            Write-Warning "PE Hash rule with hash $($HashRulePE.SHA256FlatHash) is both trusted and blocked. Skipping."
                            continue
                        }
                        $rule,$IDsAndComments = New-MicrosoftSecureBootHashRule -RuleInfo $HashRulePE -RuleMap $IDsAndComments -ErrorAction Stop
                        
                        if (-not (Set-HashRuleStaged -SHA256FlatHash $HashRulePE.SHA256FlatHash -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set Hash rule with hash $($HashRulePE.SHA256FlatHash) to STAGED."
                        }
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += ($rule.Count)
                        }
                    }

                    foreach ($HashRuleMSI in $PotentialHashRules_MSIorScript) {
                        if ( ($HashRuleMSI.Blocked -eq $true) -and (($HashRuleMSI.TrustedDriver -eq $true) -or ($HashRuleMSI.TrustedUserMode -eq $true))) {
                            Write-Warning "MSI or script Hash rule with hash $($HashRuleMSI.SHA256FlatHash) is both trusted and blocked. Skipping."
                            continue
                        }
                        $rule,$IDsAndComments = New-MicrosoftSecureBootHashRule -RuleInfo $HashRuleMSI -MSIorScript -RuleMap $IDsAndComments -ErrorAction Stop
                        
                        if (-not (Set-HashRuleStaged -SHA256FlatHash $HashRuleMSI.SHA256FlatHash -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set Hash rule with hash $($HashRuleMSI.SHA256FlatHash) to STAGED."
                        }
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += ($rule.Count)
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
                        if ( ($FileNameRule.Blocked -eq $true) -and (($FileNameRule.TrustedDriver -eq $true) -or ($FileNameRule.TrustedUserMode -eq $true))) {
                            Write-Warning "FileName rule with name $($FileNameRule.FileName) and SpecificFileNameLevel $($FileNameRule.SpecificFileNameLevel) is both trusted and blocked. Skipping."
                            continue
                        }
                        $rule,$IDsAndComments = New-MicrosoftSecureBootFileNameRule -RuleInfo $FileNameRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if (-not (Set-FileNameRuleStaged -FileName $FileNameRule.FileName -SpecificFileNameLevel $FileNameRule.SpecificFileNameLevel -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set FileName rule with name $($FileNameRule.FileName) to STAGED."
                        }
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += ($rule.Count)
                        }
                    }
                }
                "LeafCertificate" {
                    throw "This block should not be reached."
                }
                "PcaCertificate" {
                    throw "This block should not be reached."
                }
                "Certificate" {
                    $PotentialCertRules = Get-PotentialCertificateRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($CertRule in $PotentialCertRules) {
                        if ( ($CertRule.Blocked -eq $true) -and (($CertRule.TrustedDriver -eq $true) -or ($CertRule.TrustedUserMode -eq $true))) {
                            Write-Warning "Cert rule with TBS Hash $($CertRule.TBSHash) is both trusted and blocked. Skipping."
                            continue
                        }
                        $rule,$IDsAndComments = New-MicrosoftSecureBootCertificateRule -RuleInfo $CertRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -ErrorAction Stop
                        if (-not (Set-CertificateRuleStaged -TBSHash $CertRule.TBSHash -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set Certificate rule with TBSHash $($CertRule.TBSHash) to STAGED."
                        }
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += ($rule.Count)
                        }
                    }
                }
                "Publisher" {
                    $PotentialPublisherRules = Get-PotentialPublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    foreach ($PublisherRule in $PotentialPublisherRules) {
                        if ( ($PublisherRule.Blocked -eq $true) -and (($PublisherRule.TrustedDriver -eq $true) -or ($PublisherRule.TrustedUserMode -eq $true))) {
                            Write-Warning "Publisher rule with index $($PublisherRule.PublisherIndex) is both trusted and blocked. Skipping."
                            continue
                        }
                        $rule,$IDsAndComments = New-MicrosoftSecureBootPublisherRule -RuleInfo $PublisherRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -Connection $Connection -ErrorAction Stop
                        if (-not (Set-PublisherRuleStaged -PcaCertTBSHash $PublisherRule.PcaCertTBSHash -LeafCertCN $PublisherRule.LeafCertCN -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set Publisher rule with publisher name $($PublisherRule.LeafCertCN) and TBSHash $($PublisherRule.PcaCertTBSHash) to STAGED."
                        }
                        if ($rule) {
                            $RulesToMerge += $rule
                            $RulesAdded += ($rule.Count)
                        }
                    }
                }
                "FilePublisher" {
                    $PotentialFilePublisherRules = Get-PotentialFilePublisherRules -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop
                    $FilePublisherPublishers_User_Allow = @{}
                    $FilePublisherPublishers_Kernel_Allow = @{}
                    $FilePublisherPublishers_User_Deny = @{}
                    $FilePublisherPublishers_Kernel_Deny = @{}

                    foreach ($FilePublisherRule in $PotentialFilePublisherRules) {
                        if ( ($FilePublisherRule.Blocked -eq $true) -and (($FilePublisherRule.TrustedDriver -eq $true) -or ($FilePublisherRule.TrustedUserMode -eq $true))) {
                            Write-Warning "FilePublisher rule with publisher index $($FilePublisherRule.PublisherIndex) and FileName $($FilePublisherRule.FileName) is both trusted and blocked. Skipping."
                            continue
                        }

                        $TempPublisherRule = Get-WDACPublisherByPublisherIndex -PublisherIndex $FilePublisherRule.PublisherIndex -Connection $Connection -ErrorAction Stop
                        $TempPublisherRule.Comment = $null

                        if ($FilePublisherRule.Blocked -eq $true) {
                            if (-not (($FilePublisherPublishers_User_Deny[$FilePublisherRule.PublisherIndex]))) {
                            #We don't need to check if it's in $FilePublisherPublishers_Kernel_Deny because that's assumed to always mirror $FilePublisherPublishers_User_Deny

                                $TempPublisherRule.Blocked = $true
                                #We don't need to set the other properties to false, since if something is blocked, the other cases aren't dealt with
                                $rule,$IDsAndComments = New-MicrosoftSecureBootPublisherRule -RuleInfo $TempPublisherRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -Connection $Connection -ErrorAction Stop
                                foreach ($tempRule in $rule) {
                                    if ($tempRule.UserMode -eq $true) {
                                        $FilePublisherPublishers_User_Deny += @{$FilePublisherRule.PublisherIndex = $tempRule}
                                    } else {
                                        $FilePublisherPublishers_Kernel_Deny += @{$FilePublisherRule.PublisherIndex = $tempRule}
                                    }
                                }
                            }
                        }
                        else {
                            if ($FilePublisherRule.TrustedDriver -eq $true) {
                                if (-not ($FilePublisherPublishers_Kernel_Allow[$FilePublisherRule.PublisherIndex])) {
                                    $TempPublisherRule.TrustedDriver = $true
                                    $TempPublisherRule.TrustedUserMode = $false
                                    $TempPublisherRule.Blocked = $false
                                    
                                    $rule,$IDsAndComments = New-MicrosoftSecureBootPublisherRule -RuleInfo $TempPublisherRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -Connection $Connection -ErrorAction Stop
                                    
                                    if (-not ($rule.Count -eq 1)) {
                                        throw "More than one rule created for FilePublisher rule."
                                    }
                                    $FilePublisherPublishers_Kernel_Allow += @{$FilePublisherRule.PublisherIndex = $rule[0]}
                                }
                            }
                            if ($FilePublisherRule.TrustedUserMode -eq $true) {
                                if (-not ($FilePublisherPublishers_User_Allow[$FilePublisherRule.PublisherIndex])) {
                                    $TempPublisherRule.TrustedUserMode = $true
                                    $TempPublisherRule.TrustedDriver = $false
                                    $TempPublisherRule.Blocked = $false
    
                                    $rule,$IDsAndComments = New-MicrosoftSecureBootPublisherRule -RuleInfo $TempPublisherRule -RuleMap $IDsAndComments -PSModuleRoot $PSModuleRoot -Connection $Connection -ErrorAction Stop
                                    if (-not ($rule.Count -eq 1)) {
                                        throw "More than one rule created for FilePublisher rule."
                                    }
                                    $FilePublisherPublishers_User_Allow += @{$FilePublisherRule.PublisherIndex = $rule[0]}
                                }
                            }
                        }
                    }
                    foreach ($FilePublisherRule in $PotentialFilePublisherRules) {

                        #Comments are disabled for file publisher rules for now until I can figure out a way of keeping them attached to the FileAttrib or Signer rules
                        $FilePublisherRule.Comment = $null
                        $rule2,$IDsAndComments = New-MicrosoftSecureBootFilePublisherRule -RuleInfo $FilePublisherRule -RuleMap $IDsAndComments -ErrorAction Stop
                        if (-not (Set-FilePublisherRuleStaged -PublisherIndex $FilePublisherRule.PublisherIndex -FileName $FilePublisherRule.FileName -MinimumAllowedVersion $FilePublisherRule.MinimumAllowedVersion -SpecificFileNameLevel $FilePublisherRule.SpecificFileNameLevel -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set FilePublisher rule with filename $($FilePublisherRule.FileName) and publisher index $($FilePublisherRule.PublisherIndex) to STAGED."
                        }

                        if ($rule2) {
                            foreach ($tempRule in $rule2) {
                                
                                if (($FilePublisherRule.Blocked -eq $true) -and ($tempRule.UserMode -eq $true)) {
                                    ($FilePublisherPublishers_User_Deny[$FilePublisherRule.PublisherIndex]).FileAttributes += @($tempRule.Id)
                                }
                                elseif ((($FilePublisherRule.Blocked -eq $true)) -and ($tempRule.UserMode -eq $false)) {
                                    ($FilePublisherPublishers_Kernel_Deny[$FilePublisherRule.PublisherIndex]).FileAttributes += @($tempRule.Id)
                                }
                                elseif ( ($tempRule.UserMode -eq $true)) {
                                    ($FilePublisherPublishers_User_Allow[$FilePublisherRule.PublisherIndex]).FileAttributes += @($tempRule.Id)
                                }
                                elseif ( ($tempRule.UserMode -eq $false)) {
                                    ($FilePublisherPublishers_Kernel_Allow[$FilePublisherRule.PublisherIndex]).FileAttributes += @($tempRule.Id)
                                }

                                $RulesAdded += 1
                            }
                            $RulesToMerge += $rule2
                        }
                    }

                    foreach ($Signer in $FilePublisherPublishers_User_Deny.GetEnumerator()) {
                        $tempRule = $Signer.Value
                        if (($tempRule).FileAttributes.Count -ge 1) {
                            $RulesToMerge += $tempRule
                            $RulesAdded += 1
                        }
                    }
                    foreach ($Signer in $FilePublisherPublishers_Kernel_Deny.GetEnumerator()) {
                        $tempRule = $Signer.Value
                        if (($tempRule).FileAttributes.Count -ge 1) {
                            $RulesToMerge += $tempRule
                            $RulesAdded += 1
                        }
                    }
                    foreach ($Signer in $FilePublisherPublishers_User_Allow.GetEnumerator()) {
                        $tempRule = $Signer.Value
                        if (($tempRule).FileAttributes.Count -ge 1) {
                            $RulesToMerge += $tempRule
                            $RulesAdded += 1
                        }
                    }
                    foreach ($Signer in $FilePublisherPublishers_Kernel_Allow.GetEnumerator()) {
                        $tempRule = $Signer.Value
                        if (($tempRule).FileAttributes.Count -ge 1) {
                            $RulesToMerge += $tempRule
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
                Merge-CIPolicy -PolicyPaths $FullPolicyPath -Rules $RulesToMerge -OutputFilePath $TempFilePath -ErrorAction Stop | Out-Null
                #Since we've already checked for duplicate IDs, we can remove the _0 and _1 that Merge-CIPolicy puts at the end of each ID
                Remove-UnderscoreDigits -FilePath $TempFilePath -ErrorAction Stop
                Add-WDACRuleCommentsv2 -IDsAndComments $IDsAndComments -FilePath $TempFilePath -ErrorAction Stop
                Receive-FileAsPolicy -FilePath $TempFilePath -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop

                $PolicyVersion = (Get-PolicyVersionNumber -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop).PolicyVersion
                $OldPolicyPath = (Get-FullPolicyPath -PolicyGUID $Policy -ErrorAction Stop)
                if ($PolicyVersion) {
                    New-WDACPolicyVersionIncrementOne -PolicyGUID $Policy -CurrentVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
                    if (Test-WDACPolicySigned -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop) {
                        if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $Policy -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop).PolicyVersion) -Signed -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set LastSignedVersion attribute on Policy $Policy"
                        }
                    } else {
                        if (-not (Set-LastSignedUnsignedWDACPolicyVersion -PolicyGUID $Policy -PolicyVersion ((Get-PolicyVersionNumber -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop).PolicyVersion) -Unsigned -Connection $Connection -ErrorAction Stop)) {
                            throw "Could not set LastUnsignedVersion attribute on Policy $Policy"
                        }
                    }
                    $Transaction.Commit()
                    Write-Host "Successfully committed changes to Policy $Policy" -ForegroundColor Green
                    Write-Verbose "There were $RulesAdded rules that were added to this policy."
                    if ($TempFilePath) {
                        if (Test-Path $TempFilePath) {
                            Remove-Item -Path $TempFilePath -ErrorAction SilentlyContinue
                        }
                    }
                    if ($BackupOldPolicy) {
                        if ((Test-Path $BackupOldPolicy) -and (-not $PreserveBackup)) {
                            Remove-Item -Path $BackupOldPolicy -ErrorAction SilentlyContinue
                        } elseif (Test-Path $BackupOldPolicy) {
                            Write-Host "Backup old policy can be recovered at $BackupOldPolicy"
                        } else {
                            Write-Warning "Backup old policy was not able to be recovered, as the file at $BackupOldPolicy appears to be missing."
                        }
                    } elseif ($PreserveBackup) {
                        Write-Warning "Backup policy cannot be recovered, as backup file path is null."
                    }
                } else {
                    $Transaction.Rollback()
                    Remove-Variable Transaction -ErrorAction SilentlyContinue
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

            try {
                if ($HVCIOption) {
                    if ( (Get-HVCIPolicySetting -PolicyGUID $Policy -Connection $Connection -ErrorAction Stop) -ne $HVCIOption) {
                        Set-HVCIPolicySetting -PolicyGUID $Policy -HVCIOption $HVCIOption -Connection $Connection -ErrorAction Stop
                    }
                }
            } catch {
                Write-Warning $_
            }
        }

        if ($Connection) {
            $Connection.Close()
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

Export-ModuleMember -Function Merge-TrustedWDACRules