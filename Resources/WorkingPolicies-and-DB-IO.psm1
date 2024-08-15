if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
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

function Get-PolicyFileName {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $thePolicy = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $PolicyName = $thePolicy.PolicyName
        $VersionNumber = $thePolicy.PolicyVersion
        $FileName = ($PolicyName + "_v" + ($VersionNumber.replace('.','_')) + ".xml")
        return $FileName

    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }
}

function Get-FullPolicyPath {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
    $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"
    $FileName = Get-PolicyFileName -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

    if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
        return (Join-Path $WorkingPoliciesLocation -ChildPath $FileName)
    } else {
    #TODO: Other working policies directory types
    }

    return $null
}

function Receive-FileAsPolicy {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
    $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"
    $NewFileName = Get-PolicyFileName -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

    if (-not $NewFileName) {
        throw "Cannot resolve new file name for Policy $PolicyGUID"
    }

    if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
        Copy-Item $FilePath -Destination (Join-Path $WorkingPoliciesLocation -ChildPath $NewFileName) -Force -ErrorAction Stop
    } else {
    #TODO: Other working policies directory types
    }
}

function Get-PolicyXML {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $PolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        [XML]$XMLFileContent = Get-Content -Path $PolicyPath -ErrorAction Stop
        return $XMLFileContent
    } catch {
        throw $_
    }
}

function Set-XMLPolicyVersion {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$Version,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $XML = Get-PolicyXML -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $XML.SiPolicy.VersionEx = $Version
        $XML.save((Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop))
    } catch {
        throw $_
    }
}

function Set-TempXMLPolicyVersion {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$Version
    )

    try {
        [XML]$XML = Get-Content -Path $FilePath -ErrorAction Stop
        $XML.SiPolicy.VersionEx = $Version
        $XML.save($FilePath)
    } catch {
        throw $_
    }
}

function New-WDACPolicyVersionIncrementOne {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$CurrentVersion,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $FullPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $NewVersionNum = Set-IncrementVersionNumber -VersionNumber $CurrentVersion
        Set-XMLPolicyVersion -PolicyGUID $PolicyGUID -Version $NewVersionNum -Connection $Connection -ErrorAction Stop
        if (-not (Set-WDACPolicyVersion -PolicyGUID $PolicyGUID -Version $NewVersionNum -Connection $Connection -ErrorAction Stop)) {
            throw "Unable to update policy version in database."
        }
        Rename-Item -Path $FullPath -NewName (Get-PolicyFileName -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) -Force -ErrorAction Stop
    } catch {
        throw $_
    }
}

function Backup-CurrentPolicy {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $PolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
        $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"

        $FileName = Split-Path $PolicyPath -Leaf
        $NewFileName = ($FileName + "_old.xml")
        if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
            #return (Join-Path $WorkingPoliciesLocation -ChildPath $FileName)
            Copy-Item $PolicyPath -Destination (Join-Path $WorkingPoliciesLocation -ChildPath $NewFileName) -Force -ErrorAction Stop
        } else {
        #TODO: Other working policies directory types
        }
        
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }

}

function Get-WDACHollowPolicy {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        $TempPolicyPath,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        [XML]$XMLFileContent = Get-PolicyXML -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        if (-not $TempPolicyPath) {
            $TempPolicyPath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
        }
        
        if ($XMLFileContent.SiPolicy.CiSigners) {
            $XMLFileContent.SiPolicy.CiSigners.innerText = $null
        }
        if ($XMLFileContent.SiPolicy.Signers) {
            $XMLFileContent.SiPolicy.Signers.innerText = $null
        }
        if ($XMLFileContent.SiPolicy.UpdatePolicySigners) {
            $XMLFileContent.SiPolicy.UpdatePolicySigners.innerText = $null
        }
        if ($XMLFileContent.SiPolicy.SupplementalPolicySigners) {
            $XMLFileContent.SiPolicy.SupplementalPolicySigners.innerText = $null
        }
        if ($XMLFileContent.SiPolicy.FileRules) {
            $XMLFileContent.SiPolicy.FileRules.innerText = $null
        }
        if ($XMLFileContent.SiPolicy.EKUs) {
            $XMLFileContent.SiPolicy.EKUs.innerText = $null
        }
    
        foreach ($SigningScenario in $XMLFileContent.SiPolicy.SigningScenarios.SigningScenario.ID) {
            if (($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners) {
                ($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.innerText = $null
            }
        }
    
        $XMLFileContent.Save($TempPolicyPath)
    
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $TempPolicyPath
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }
}

function Set-UpdatedWDACPolicyContent {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $SourcePolicyPath,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $DestinationPolicyPath
    )

    if ((-not (Test-Path $SourcePolicyPath)) -or (-not (Test-Path $DestinationPolicyPath))) {
        throw "One of the file paths provided does not exist."
    }

    try {
        [System.Xml.XmlDocument]$DestinationPolicyContent =  Get-Content -Path $DestinationPolicyPath -ErrorAction Stop
        [System.Xml.XmlDocument]$SourcePolicyContent = Get-Content -Path $SourcePolicyPath -ErrorAction Stop
        $namespaceUri = "urn:schemas-microsoft-com:sipolicy"
        $namespaceManager = New-Object System.Xml.XmlNamespaceManager($SourcePolicyContent.NameTable)
        $namespaceManager.AddNamespace("ns", $namespaceUri)

        $CiSignersSource = $SourcePolicyContent.SelectSingleNode("//ns:CiSigners", $namespaceManager)
        if ($CiSignersSource -and ("" -ne $CiSignersSource.InnerXml.Trim())) {
            $CiSignersDestination = $DestinationPolicyContent.SelectSingleNode("//ns:CiSigners", $namespaceManager)
            if ($CiSignersDestination) {
                $CiSignersDestination.ParentNode.RemoveChild($CiSignersDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($CiSignersSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }

        $SignersSource = $SourcePolicyContent.SelectSingleNode("//ns:Signers", $namespaceManager)
        if ($SignersSource -and ("" -ne $SignersSource.InnerXml.Trim())) {
            $SignersDestination = $DestinationPolicyContent.SelectSingleNode("//ns:Signers",$namespaceManager)
            if ($SignersDestination) {
                $SignersDestination.ParentNode.RemoveChild($SignersDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($SignersSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }

        $SupplementalPolicySignersSource = $SourcePolicyContent.SelectSingleNode("//ns:SupplementalPolicySigners", $namespaceManager)
        if ($SupplementalPolicySignersSource -and ("" -ne $SupplementalPolicySignersSource.InnerXml.Trim())) {
            $SupplementalPolicySignersDestination = $DestinationPolicyContent.SelectSingleNode("//ns:SupplementalPolicySigners",$namespaceManager)
            if ($SupplementalPolicySignersDestination) {
                $SupplementalPolicySignersDestination.ParentNode.RemoveChild($SupplementalPolicySignersDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($SupplementalPolicySignersSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }

        $UpdatePolicySignersSource = $SourcePolicyContent.SelectSingleNode("//ns:UpdatePolicySigners", $namespaceManager)
        if ($UpdatePolicySignersSource -and ("" -ne $UpdatePolicySignersSource.InnerXml.Trim())) {
            $UpdatePolicySignersDestination = $DestinationPolicyContent.SelectSingleNode("//ns:UpdatePolicySigners",$namespaceManager)
            if ($UpdatePolicySignersDestination) {
                $UpdatePolicySignersDestination.ParentNode.RemoveChild($UpdatePolicySignersDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($UpdatePolicySignersSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }

        $FileRulesSource = $SourcePolicyContent.SelectSingleNode("//ns:FileRules", $namespaceManager)
        if ($FileRulesSource -and ("" -ne $FileRulesSource.InnerXml.Trim())) {
            $FileRulesDestination = $DestinationPolicyContent.SelectSingleNode("//ns:FileRules",$namespaceManager)
            if ($FileRulesDestination) {
                $FileRulesDestination.ParentNode.RemoveChild($FileRulesDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($FileRulesSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }

        $EKUsSource = $SourcePolicyContent.SelectSingleNode("//ns:EKUs", $namespaceManager)
        if ($EKUsSource -and ("" -ne $EKUsSource.InnerXml.Trim())) {
            $EKUsDestination = $DestinationPolicyContent.SelectSingleNode("//ns:EKUs",$namespaceManager)
            if ($EKUsDestination) {
                $EKUsDestination.ParentNode.RemoveChild($EKUsDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($EKUsSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }

        $SigningScenariosSource = $SourcePolicyContent.SelectSingleNode("//ns:SigningScenarios", $namespaceManager)
        if ($SigningScenariosSource -and ("" -ne $SigningScenariosSource.InnerXml.Trim())) {
            $SigningScenariosDestination = $DestinationPolicyContent.SelectSingleNode("//ns:SigningScenarios",$namespaceManager)
            if ($SigningScenariosDestination) {
                $SigningScenariosDestination.ParentNode.RemoveChild($SigningScenariosDestination)
            }
            $importedNode = $DestinationPolicyContent.ImportNode($SigningScenariosSource,$true)
            $DestinationPolicyContent.DocumentElement.AppendChild($importedNode)
            $DestinationPolicyContent.Save($DestinationPolicyPath) | Out-Null
        }
    } catch {
        throw ($_ | Format-List -Property * | Out-String)
    }
}

function Get-HVCIPolicySetting {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        [XML]$XMLFileContent = Get-PolicyXML -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        
        $result = $null

        if ($XMLFileContent.SiPolicy.HvciOptions) {
            $result = $XMLFileContent.SiPolicy.HvciOptions
        }
        
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        
        return $result

    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }
}

function Set-HVCIPolicySetting {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$HVCIOption,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $FullPolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        switch ($HVCIOption) {
            0 {
                Set-HVCIOptions -FilePath $FullPolicyPath -None -ErrorAction Stop
            }
            1 {
                Set-HVCIOptions -FilePath $FullPolicyPath -Enabled -ErrorAction Stop
            }
            2 {
                Set-HVCIOptions -FilePath $FullPolicyPath -Strict -ErrorAction Stop
            }
            Default {
                throw "$HVCIOption is not a valid HVCI option."
            }
        }

        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }

}