if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

function Get-PotentialHashRules {
    [CmdletBinding()]
    Param (
        [switch]$MSIorScript,
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($MSIorScript) {
            if ($PolicyGUID) {
                $Command.Commandtext = "Select * from msi_or_script WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND (AllowedPolicyID = @PolicyGUID OR BlockingPolicyID = @PolicyGUID)"
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            } else {
                $Command.Commandtext = "Select * from msi_or_script WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
            }
        } else {
            if ($PolicyGUID) {
                $Command.Commandtext = "Select * from apps WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND (AllowedPolicyID = @PolicyGUID OR BlockingPolicyID = @PolicyGUID)"
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            } else {
                $Command.Commandtext = "Select * from apps WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
            }
        }

        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                if ($MSIorScript) {
                    $result += [PSCustomObject]@{
                        SHA256FlatHash = $Reader["SHA256FlatHash"];
                        SHA1FlatHash = $Reader["SHA1FlatHash"];
                        TimeDetected = $Reader["TimeDetected"];
                        FirstDetectedPath = $Reader["FirstDetectedPath"];
                        FirstDetectedUser = $Reader["FirstDetectedUser"];
                        FirstDetectedProcessID = ($Reader["FirstDetectedProcessID"]);
                        SHA256AuthenticodeHash = $Reader["SHA256AuthenticodeHash"];
                        SHA256SipHash = $Reader["SHA256SipHash"];
                        UserWriteable = [bool]($Reader["UserWriteable"]);
                        Signed = [bool]($Reader["Signed"]);
                        OriginDevice = $Reader["OriginDevice"];
                        EventType = $Reader["EventType"];
                        AppIndex = $Reader["AppIndex"];
                        Untrusted = [bool]($Reader["Untrusted"]);
                        TrustedDriver = [bool]($Reader["TrustedDriver"]);
                        TrustedUserMode = [bool]($Reader["TrustedUserMode"]);
                        Staged = [bool]($Reader["Staged"]);
                        Revoked = [bool]($Reader["Revoked"]);
                        Deferred = [bool]($Reader["Deferred"]);
                        Blocked = [bool]($Reader["Blocked"]);
                        BlockingPolicyID = $Reader["BlockingPolicyID"];
                        AllowedPolicyID = $Reader["AllowedPolicyID"];
                        DeferredPolicyIndex = $Reader["DeferredPolicyIndex"];
                        Comment = $Reader["Comment"]
                    }
                }
                else {
                    $result += [PSCustomObject]@{
                        SHA256FlatHash = $Reader["SHA256FlatHash"];
                        FileName = $Reader["FileName"];
                        TimeDetected = $Reader["TimeDetected"];
                        FirstDetectedPath = $Reader["FirstDetectedPath"];
                        FirstDetectedUser = $Reader["FirstDetectedUser"];
                        FirstDetectedProcessID = ($Reader["FirstDetectedProcessID"]);
                        FirstDetectedProcessName = $Reader["FirstDetectedProcessName"];
                        SHA256AuthenticodeHash = $Reader["SHA256AuthenticodeHash"];
                        SHA1AuthenticodeHash = $Reader["SHA1AuthenticodeHash"];
                        SHA256PageHash = $Reader["SHA256PageHash"];
                        SHA1PageHash = $Reader["SHA1PageHash"];
                        SHA256SipHash = $Reader["SHA256SipHash"];
                        OriginDevice  = $Reader["OriginDevice"];
                        EventType = $Reader["EventType"];
                        SigningScenario = $Reader["SigningScenario"];
                        OriginalFileName = $Reader["OriginalFileName"];
                        FileVersion = $Reader["FileVersion"];
                        InternalName = $Reader["InternalName"];
                        FileDescription  = $Reader["FileDescription"];
                        ProductName = $Reader["ProductName"];
                        PackageFamilyName = $Reader["PackageFamilyName"];
                        UserWriteable = [bool]($Reader["UserWriteable"]);
                        FailedWHQL = [bool]($Reader["FailedWHQL"]);
                        Trusted = [bool]($Reader["Trusted"]);
                        TrustedDriver = [bool]($Reader["TrustedDriver"]);
                        TrustedUserMode = [bool]($Reader["TrustedUserMode"]);
                        Staged = [bool]($Reader["Staged"]);
                        Revoked = [bool]($Reader["Revoked"]);
                        Deferred = [bool]($Reader["Deferred"]);
                        Blocked = [bool]($Reader["Blocked"]);
                        BlockingPolicyID = $Reader["BlockingPolicyID"];
                        AllowedPolicyID = $Reader["AllowedPolicyID"];
                        DeferredPolicyIndex = ($Reader["DeferredPolicyIndex"]);
                        Comment = $Reader["Comment"];
                        AppIndex = ($Reader["AppIndex"]);
                        RequestedSigningLevel = $Reader["RequestedSigningLevel"];
                        ValidatedSigningLevel = $Reader["ValidatedSigningLevel"]
                    }
                }
            }
        }
        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return (Format-SQLResult $result)
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $theError
    }
}

function Set-HashRuleStaged {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [switch]$Unset,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()

        if (Find-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection) {
            if ($Unset) {
                $Command.Commandtext = "UPDATE apps SET Staged = 0 WHERE SHA256FlatHash = @SHA256FlatHash"
            } else {
                $Command.Commandtext = "UPDATE apps SET Staged = 1 WHERE SHA256FlatHash = @SHA256FlatHash"
            }
        }
        elseif (Find-MSIorScript -SHA256FlatHash $SHA256FlatHash -Connection $Connection) {
            if ($Unset) {
                $Command.Commandtext = "UPDATE msi_or_script SET Staged = 0 WHERE SHA256FlatHash = @SHA256FlatHash"
            } else {
                $Command.Commandtext = "UPDATE msi_or_script SET Staged = 1 WHERE SHA256FlatHash = @SHA256FlatHash"
            }
        } else {
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }
            return
        }

        $Command.Parameters.AddWithValue("SHA256FlatHash",$SHA256FlatHash) | Out-Null
        $Command.ExecuteNonQuery()

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

function Get-PotentialFilePathRules {
    [CmdletBinding()]
    Param (
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    #TODO
}

function Set-FilePathRuleStaged {
    [CmdletBinding()]
    Param (
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    #TODO
}

function Get-PotentialFileNameRules {
    [CmdletBinding()]
    Param (
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($PolicyGUID) {
            $Command.Commandtext = "Select * from file_names WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND (AllowedPolicyID = @PolicyGUID OR BlockingPolicyID = @PolicyGUID)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        } else {
            $Command.Commandtext = "Select * from file_names WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        }
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
 
        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    FileName = $Reader["FileName"];
                    SpecificFileNameLevel = $Reader["SpecificFileNameLevel"];
                    Untrusted = [bool]$Reader["Untrusted"];
                    TrustedDriver = [bool]($Reader["TrustedDriver"]);
                    TrustedUserMode = [bool]$Reader["TrustedUserMode"];
                    Staged = [bool]$Reader["Staged"];
                    Revoked = [bool]$Reader["Revoked"];
                    Deferred = [bool]($Reader["Deferred"]);
                    Blocked = [bool]($Reader["Blocked"]);
                    AllowedPolicyID = ($Reader["AllowedPolicyID"]);
                    DeferredPolicyIndex = $Reader["DeferredPolicyIndex"];
                    Comment = $Reader["Comment"];
                    BlockingPolicyID = $Reader["BlockingPolicyID"];
                }
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return (Format-SQLResult $result)
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $theError
    }
}

function Set-FileNameRuleStaged {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SpecificFileNameLevel,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE file_names SET Staged = 1 WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.ExecuteNonQuery()

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

function Get-PotentialCertificateRules {
    [CmdletBinding()]
    Param (
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($PolicyGUID) {
            $Command.Commandtext = "Select * from certificates WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND (AllowedPolicyID = @PolicyGUID OR BlockingPolicyID = @PolicyGUID)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        } else {
            $Command.Commandtext = "Select * from certificates WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        }
        
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    TBSHash = $Reader["TBSHash"];
                    CommonName = $Reader["CommonName"];
                    ParentCertTBSHash = $Reader["ParentCertTBSHash"];
                    NotValidBefore = $Reader["NotValidBefore"];
                    NotValidAfter = $Reader["NotValidAfter"];
                    Untrusted = [bool]($Reader["Untrusted"]);
                    TrustedDriver = [bool]($Reader["TrustedDriver"]);
                    TrustedUserMode = [bool]($Reader["TrustedUserMode"]);
                    Staged = [bool]($Reader["Staged"]);
                    Revoked = [bool]($Reader["Revoked"]);
                    Deferred = [bool]($Reader["Deferred"]);
                    Blocked = [bool]($Reader["Blocked"]);
                    AllowedPolicyID = $Reader["AllowedPolicyID"];
                    DeferredPolicyIndex = $Reader["DeferredPolicyIndex"];
                    Comment = $Reader["Comment"];
                    BlockingPolicyID = $Reader["BlockingPolicyID"]
                }
            }
        }

        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return (Format-SQLResult $result)
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $theError
    }
}

function Get-PotentialLeafCertificateRules {
    [CmdletBinding()]
    Param (
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    return (Get-PotentialCertificateRules -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)
}

function Get-PotentialPcaCertificateRules {
    [CmdletBinding()]
    Param (
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    return (Get-PotentialCertificateRules -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)
}

function Set-CertificateRuleStaged {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$TBSHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE certificates SET Staged = 1 WHERE TBSHash = @TBSHash"
        $Command.Parameters.AddWithValue("TBSHash",$TBSHash) | Out-Null
        $Command.ExecuteNonQuery()

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

function Get-PotentialPublisherRules {
    [CmdletBinding()]
    Param (
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($PolicyGUID) {
            $Command.Commandtext = "Select * from publishers WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND (AllowedPolicyID = @PolicyGUID OR BlockingPolicyID = @PolicyGUID)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        } else {
            $Command.Commandtext = "Select * from publishers WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        }
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    LeafCertCN = $Reader["LeafCertCN"];
                    PcaCertTBSHash = $Reader["PcaCertTBSHash"];
                    Untrusted = [bool]($Reader["Untrusted"]);
                    TrustedDriver = [bool]$Reader["TrustedDriver"];
                    TrustedUserMode = [bool]$Reader["TrustedUserMode"];
                    Staged = [bool]$Reader["Staged"];
                    Revoked = [bool]($Reader["Revoked"]);
                    Deferred = [bool]($Reader["Deferred"]);
                    Blocked = [bool]($Reader["Blocked"]);
                    PublisherTBSHash = $Reader["PublisherTBSHash"];
                    AllowedPolicyID = $Reader["AllowedPolicyID"];
                    DeferredPolicyIndex = $Reader["DeferredPolicyIndex"];
                    Comment = $Reader["Comment"];
                    BlockingPolicyID = $Reader["BlockingPolicyID"];
                    PublisherIndex = $Reader["PublisherIndex"]
                }
            }
        }

        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return (Format-SQLResult $result)
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $theError
    }
}

function Set-PublisherRuleStaged {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PcaCertTBSHash,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$LeafCertCN,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE publishers SET Staged = 1 WHERE PcaCertTBSHash = @PcaCertTBSHash AND LeafCertCN = @LeafCertCN"
        $Command.Parameters.AddWithValue("PcaCertTBSHash",$PcaCertTBSHash) | Out-Null
        $Command.Parameters.AddWithValue("LeafCertCN",$LeafCertCN) | Out-Null
        $Command.ExecuteNonQuery()

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

function Get-PotentialFilePublisherRules {
    [CmdletBinding()]
    Param (
        $PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
       
        if ($PolicyGUID) {
            $Command.Commandtext = "Select * from file_publishers WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND (AllowedPolicyID = @PolicyGUID OR BlockingPolicyID = @PolicyGUID)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        } else {
            $Command.Commandtext = "Select * from file_publishers WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        }
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    PublisherIndex = $Reader["PublisherIndex"];
                    Untrusted = [bool]$Reader["Untrusted"];
                    TrustedDriver = [bool]($Reader["TrustedDriver"]);
                    TrustedUserMode = [bool]$Reader["TrustedUserMode"];
                    Staged = [bool]$Reader["Staged"];
                    Revoked = [bool]$Reader["Revoked"];
                    Deferred = [bool]($Reader["Deferred"]);
                    Blocked = [bool]($Reader["Blocked"]);
                    AllowedPolicyID = ($Reader["AllowedPolicyID"]);
                    DeferredPolicyIndex = $Reader["DeferredPolicyIndex"];
                    Comment = $Reader["Comment"];
                    BlockingPolicyID = $Reader["BlockingPolicyID"];
                    MinimumAllowedVersion = $Reader["MinimumAllowedVersion"];
                    MaximumAllowedVersion = $Reader["MaximumAllowedVersion"];
                    FileName = $Reader["FileName"];
                    SpecificFileNameLevel = $Reader["SpecificFileNameLevel"]
                }
            }
        }

        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return (Format-SQLResult $result)
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $theError
    }
}

function Set-FilePublisherRuleStaged {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PublisherIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$MinimumAllowedVersion,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SpecificFileNameLevel,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE file_publishers SET Staged = 1 WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("MinimumAllowedVersion",$MinimumAllowedVersion) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.ExecuteNonQuery()

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

function Get-PolicyVersionNumber {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select PolicyVersion from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    PolicyVersion = $Reader["PolicyVersion"]
                }
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return (Format-SQLResult $result)
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $theError
    }
}