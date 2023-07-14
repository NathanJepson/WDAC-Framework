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

    try {
        $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
        $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"

        if (-not $WorkingPoliciesLocation -or -not $WorkingPoliciesLocationType -or "" -eq $WorkingPoliciesLocation -or "" -eq $WorkingPoliciesLocationType) {
            throw "Null or invalid values provided for Working Policies location (or the location type)"
        }
    } catch {
        Write-Verbose $_
        throw "Trouble in retrieving your working policies location."
        return
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
        for ($i=0; $i -lt $Rules.Count; $i++) {
            $TempString = $Rules[$i].Option
            if ($TempString -eq "Enabled:Audit Mode") {
                $AuditMode = $true
            }
            if ($TempString -eq "Enabled:Unsigned System Integrity Policy") {
                $IsSigned = $false
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
            return
        }

        Write-Verbose "Policy Import successful."

    } catch {
        $theError = $_
        if ($Transaction) {
            $Transaction.Rollback()
        }

        if ($Connection) {
            $Connection.Close()
        }
        throw $theError
    }
}