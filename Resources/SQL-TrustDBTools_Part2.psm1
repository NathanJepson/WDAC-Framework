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
            $Command.Commandtext = "Select * from msi_or_script WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        } else {
            $Command.Commandtext = "Select * from apps WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        }

        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                if ($MSIorScript) {
                    $result += [PSCustomObject]@{
                        SHA256FlatHash = $Reader["SHA256FlatHash"];
                        TimeDetected = $Reader["TimeDetected"];
                        FirstDetectedPath = $Reader["FirstDetectedPath"];
                        FirstDetectedUser = $Reader["FirstDetectedUser"];
                        FirstDetectedProcessID = ($Reader["FirstDetectedProcessID"]);
                        SHA256AuthenticodeHash = $Reader["SHA256AuthenticodeHash"];
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
        return $result
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

function Get-PotentialFilePathRules {
    [CmdletBinding()]
    Param (
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
}

function Get-PotentialFileNameRules {
    [CmdletBinding()]
    Param (
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
        $Command.Commandtext = "Select * from file_names WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.Read()) {
            $result = @()
        }
        while($Reader.HasRows) {
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
        return $result
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
        $Command.Commandtext = "Select * from certificates WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND IsLeaf = 1"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    TBSHash = $Reader["TBSHash"];
                    CommonName = $Reader["CommonName"];
                    IsLeaf = [bool]($Reader["IsLeaf"]);
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
        return $result
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

function Get-PotentialPcaCertificateRules {
    [CmdletBinding()]
    Param (
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
        $Command.Commandtext = "Select * from certificates WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0 AND IsLeaf = 0"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    TBSHash = $Reader["TBSHash"];
                    CommonName = $Reader["CommonName"];
                    IsLeaf = [bool]($Reader["IsLeaf"]);
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
        return $result
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

function Get-PotentialPublisherRules {
    [CmdletBinding()]
    Param (
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
        $Command.Commandtext = "Select * from publishers WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
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
        return $result
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

function Get-PotentialFilePublisherRules {
    [CmdletBinding()]
    Param (
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
       
        $Command.Commandtext = "Select * from file_publishers WHERE (TrustedDriver = 1 OR TrustedUserMode = 1 OR Blocked = 1) AND Staged = 0"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
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
                    MinimumAllowedVersion = $VersionNumMinTmp;
                    MaximumAllowedVersion = $VersionNumMaxTmp;
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
        return $result
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
        return $result
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