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
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        [XML]$XMLFileContent = Get-PolicyXML -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $TempPolicyPath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( ([string](New-Guid)) + ".xml")))
        
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
            if (($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.AllowedSigners) {
                ($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.AllowedSigners.innerText = $null
            }
            if (($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.DeniedSigners) {
                ($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.DeniedSigners.innerText = $null
            }
            if (($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.FileRulesRef) {
                ($XMLFileContent.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.ID -eq $SigningScenario}).ProductSigners.FileRulesRef.innerText = $null
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