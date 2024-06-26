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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\WorkingPolicies-and-DB-IO.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\WorkingPolicies-and-DB-IO.psm1")
}

function Test-InvalidValidFileNameChars {
#Invalid characters: \ / : * ? " < > |
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileChars
    )


    return ($FileChars -match "(\\|\/|\:|\*|\?|\`"|\<|\>|\|)")
}

function Remove-CurlyBracesPolicyID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $InputPolicyString
    )

    if (-not $InputPolicyString) {
        return $null
    }

    if ($InputPolicyString -match "\{") {
        $InputPolicyString = $InputPolicyString.replace('{','');
    }
    if ($InputPolicyString -match "\}") {
        $InputPolicyString = $InputPolicyString.replace('}','');
    }

    return $InputPolicyString
}   

function Import-WDACPolicy {
    <#
    .SYNOPSIS
    Import-WDACPolicy will import a designated XML WDAC Policy into your database, as well as into your working policies directory (with the correctly
    formatted name as understand by WDAC-Framework)

    .DESCRIPTION
    When putting the designated policy in the database, attributes such as policy name, and policy version, will be pulled from the content
    of the .XML file. When -Pillar is designated, the pillar attribute for the policy is set in the database (indicating that EVERY workstation
    in the database will be assigned this policy)

    .EXAMPLE
    Import-WDACPolicy -FilePath "C:\Users\user1\Documents\Policies\WDACPolicy1.xml"

    .EXAMPLE
    Import-WDACPolicy -FilePath "C:\Users\user1\Documents\Policies\WDACPolicy1.xml" -Pillar

    Author: Nathan Jepson
    License: MIT License
    
    #>
    [CmdletBinding()]
    Param (
        [ValidatePattern('\.xml$')]
        [ValidateScript({Test-Path $_}, ErrorMessage = "Cannot find the the provided FilePath.")]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Alias("IsPillar")]
        [switch]$Pillar
    )

    if ($ThisIsASignedModule) {
        Write-Verbose "The current file is in the SignedModules folder."
    }

    try {
        $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
        $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"

        if (-not $WorkingPoliciesLocation -or -not $WorkingPoliciesLocationType -or "" -eq $WorkingPoliciesLocation -or "" -eq $WorkingPoliciesLocationType) {
            throw "Null or invalid values provided for Working Policies location (or the location type)"
        }
    } catch {
        Write-Verbose $_
        throw "Trouble in retrieving your working policies location."
    }


    try {
        [XML]$XMLFileContent = Get-Content -Path $FilePath -ErrorAction Stop
        $VersionNumber = $XMLFileContent.SiPolicy.VersionEx
        $PolicyID = $XMLFileContent.SiPolicy.PolicyID
        $BasePolicyID = $XMLFileContent.SiPolicy.BasePolicyID
        $OtherPolicyIDInfo = Get-CIPolicyIdInfo -FilePath $FilePath
        $OtherPolicyID = ($OtherPolicyIDInfo | Where-Object {$_.ValueName -eq "Id"}).Value
        $PolicyName = ($OtherPolicyIDInfo | Where-Object {$_.ValueName -eq "Name"}).Value

        if (-not $PolicyID -or -not $BasePolicyID) {
            throw "No valid PolicyID or BasePolicyID was found in the provided file."
        } 

        if (Test-InvalidValidFileNameChars -FileChars $PolicyName) {
            throw "The policy name contains invalid characters. Please use valid characters which are valid for file paths and file names."
        }

        $NewPolicyFileName = ($PolicyName + "_v" + ($VersionNumber.replace('.','_')) + ".xml")
        
        #RemoveCurlyBraces
        $PolicyID = Remove-CurlyBracesPolicyID -InputPolicyString $PolicyID
        $BasePolicyID = Remove-CurlyBracesPolicyID -InputPolicyString $BasePolicyID

        if (Find-WDACPolicy -PolicyGUID $PolicyID -ErrorAction Stop) {
            throw "A base policy of ID $PolicyID already exists in the database."
        }

        if (Find-WDACPolicyByID -PolicyID $OtherPolicyID -ErrorAction SilentlyContinue) {
            Write-Warning "Other policy with instance of ID $OtherPolicyID already exists in the database."
        }
        
        $BaseOrSupplemental = $false
        $ParentPolicy = $null
        if ($PolicyID -ne $BasePolicyID) {
            $BaseOrSupplemental = $true
            $ParentPolicy = $BasePolicyID
        } 

        $Rules = ($XMLFileContent.SIPolicy.Rules | Select-Object -Expand Rule)
        $IsSigned = $true
        $AuditMode = $false
        if ($Rules.Count -eq 1) {
            if ($Rules.Option -eq "Enabled:Audit Mode") {
                $AuditMode = $true
            }
            if ($Rules.Option -eq "Enabled:Unsigned System Integrity Policy") {
                $IsSigned = $false
            }
        } else {
            for ($i=0; $i -lt $Rules.Count; $i++) {
                $TempString = $Rules[$i].Option
                if ($TempString -eq "Enabled:Audit Mode") {
                    $AuditMode = $true
                }
                if ($TempString -eq "Enabled:Unsigned System Integrity Policy") {
                    $IsSigned = $false
                }
            }
        }
        
        if ($IsSigned) {
            Write-Warning "This will be a signed policy. Verify if this is correct."
        }
        if (-not $AuditMode) {
            Write-Warning "This will be an enforced (i.e., non audit) policy. Verify if this is correct."
        }

        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        
        if (-not (Add-WDACPolicy -PolicyGUID $PolicyID -PolicyID $OtherPolicyID -PolicyName $PolicyName -PolicyVersion $VersionNumber -ParentPolicyGUID $ParentPolicy -BaseOrSupplemental $BaseOrSupplemental -IsSigned $IsSigned -AuditMode $AuditMode -IsPillar $Pillar.ToBool() -OriginLocation $WorkingPoliciesLocation -OriginLocationType $WorkingPoliciesLocationType -Connection $Connection -ErrorAction Stop)) {
            throw "Failed to add this policy to the database."
        }
        
        try {
            
            if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
                Copy-Item $FilePath -Destination (Join-Path $WorkingPoliciesLocation -ChildPath $NewPolicyFileName) -Force -ErrorAction Stop
            } else {
            #TODO: Other working policies directory types
            }
            
            $Transaction.Commit()
            $Connection.Close()
            Remove-Variable Transaction, Connection -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose $_
            throw "There was a problem placing the new policy file into your working policies directory."
        }

        Write-Verbose "Policy Import successful."

    } catch {
        $theError = $_
        if ($Transaction -and $Connection) {
            if ($Connection.AutoCommit -eq $false) {
                $Transaction.Rollback()
            }
        }

        if ($Connection) {
            $Connection.Close()
        }
        throw $theError
    }
}

Export-ModuleMember -Function Import-WDACPolicy