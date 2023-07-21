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

function Import-SQLite {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$SqliteAssembly
    )

    if (-not $SqliteAssembly) {
        try {
            $TrueSqliteAssembly = (Get-LocalStorageJSON)."SqliteAssembly"
            if (-not $TrueSqliteAssembly) {
                throw "No valid value for Sqlite binary provided from local storage."
            }
            $SqliteAssembly = $TrueSqliteAssembly
        } catch {
            Write-Verbose $_
            throw "Unable to read or process the file path for the Sqlite binary."
        }
    }

    try {
        #This could throw off some EDR or anti-virus solutions
        [Reflection.Assembly]::LoadFile($SqliteAssembly) | Out-Null

        try {
            Set-ValueLocalStorageJSON -Key "SqliteAssembly" -Value $SqliteAssembly -ErrorAction Stop
        } catch {
            Write-Warning "Unable to update cached Sqlite binary."
        }
    } catch [NotSupportedException] {
        throw "This Sqlite binary is not supported in this version of PowerShell.";
    } catch {
        Write-Verbose $_;
        throw "Could not load the Sqlite binary.";
    }
}

function New-SqliteConnection {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Database
    )

    if (-not ($Database)) {
        $TrueDatabase = (Get-LocalStorageJSON)."WorkingDatabase"."Location"
        #TODO: Handle other location types
        if (-not $TrueDatabase) {
            throw "No valid Database provided."
        }
        $Database = $TrueDatabase 
    }

    try {
        $sDatabaseConnectionString=[string]::Format("data source={0}",$Database)
        $oSQLiteDBConnection = New-Object System.Data.SQLite.SQLiteConnection -ErrorAction Stop
        $oSQLiteDBConnection.ConnectionString = $sDatabaseConnectionString
        $oSQLiteDBConnection.open()
        return $oSQLiteDBConnection
    } catch {
        throw $_
    }
}

function Compare-Versions {
#Source: https://www.geeksforgeeks.org/compare-two-version-numbers/
    Param(
        $Version1,
        $Version2
    )
    $vnum1,$vnum2 = 0;

    for ($i=$j=0; $i -lt $Version1.Length -or $j -lt $Version2.Length;) {
        while ($i -lt ($version1.Length) -and ($Version1[$i] -ne ".")) {
            $vnum1 = ($vnum1 * 10) + [int]($Version1[$i]);
            $i++;
        }
        while ($j -lt ($Version2.Length) -and ($Version2[$j] -ne ".")) {
            $vnum2 = ($vnum2 * 10) + [int]($Version2[$j]);
            $j++;
        }

        if ($vnum1 -gt $vnum2) {
            return 1; #Version1 is bigger
        } 
        if ($vnum2 -gt $vnum1) {
            return -1; #Version2 is bigger
        }
        $vnum1,$vnum2 = 0; 
        $i++;
        $j++
    }
    return 0; #They are the same version number
}

function Find-WDACGroup {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $GroupName
    )

    $result = $false

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from GROUPS WHERE GroupName = @GroupName"
        $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
            }
        }
        $Reader.Close()
        $Connection.close()
        return $result
    } catch {
        throw $_
    }
}

function New-WDACGroup_SQL {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $GroupName
    )

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO GROUPS (GroupName) VALUES (@GroupName)"
        $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
        $Command.ExecuteNonQuery()
        $Connection.close()
    } catch {
        throw $_
    }
}

function Get-WDACGroups {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "SELECT GroupName From groups;"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
                    GroupName = ($Reader["GroupName"]);
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

function Get-MAXAppIndexID {
    [cmdletbinding()]
    Param ( 
        [switch]$isMSIorScript,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null;
    $NoConnectionProvided = $false;

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($isMSIorScript) {
            $Command.Commandtext = "Select MAX(AppIndex) from msi_or_script"
        } else {        
            $Command.Commandtext = "Select MAX(AppIndex) from apps"
        }
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $Reader["MAX(AppIndex)"]
                if ($result -is [System.DBNull]) {
                    $Reader.Close()
                    $Connection.close()
                    return $null
                } else {
                    $Reader.Close()
                    $Connection.close()
                    return $result
                }
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $result
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.close()
        }
        throw $_
    }
}

function Find-WDACApp {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from apps WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $result
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $_
    }
}

function Get-WDACApp {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from apps WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $Result = [PSCustomObject]@{
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

function Get-WDACAppSigners {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$AppIndex,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from signers WHERE AppIndex = @AppIndex"
        $Command.Parameters.AddWithValue("AppIndex",$AppIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
                    AppIndex = [int]($Reader["AppIndex"]);
                    SignatureIndex = [int]($Reader["SignatureIndex"]);
                    CertificateTBSHash = $Reader["CertificateTBSHash"];
                    SignatureType = $Reader["SignatureType"];
                    PageHash = $Reader["PageHash"];
                    Flags = $Reader["Flags"];
                    PolicyBits = $Reader["PolicyBits"];
                    ValidatedSigningLevel = $Reader["ValidatedSigningLevel"];
                    VerificationError = $Reader["VerificationError"]
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

function Get-WDACAppSignersByFlatHash {
    [cmdletbinding()]
    param(
        [string]$SHA256FlatHash
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "SELECT * From signers WHERE AppIndex = (SELECT AppIndex from apps WHERE SHA256FlatHash = @SHA256FlatHash);"
        $Command.Parameters.AddWithValue("SHA256FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
                    AppIndex = [int]($Reader["AppIndex"]);
                    SignatureIndex = [int]($Reader["SignatureIndex"]);
                    CertificateTBSHash = $Reader["CertificateTBSHash"];
                    SignatureType = $Reader["SignatureType"];
                    PageHash = $Reader["PageHash"];
                    Flags = $Reader["Flags"];
                    PolicyBits = $Reader["PolicyBits"];
                    ValidatedSigningLevel = $Reader["ValidatedSigningLevel"];
                    VerificationError = $Reader["VerificationError"]
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

function Get-WDACAppsToSetTrust {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from apps WHERE Untrusted = 0 AND TrustedDriver = 0 AND TrustedUserMode = 0 AND Staged = 0 AND Revoked = 0 AND Deferred = 0 AND Blocked = 0"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
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

function Add-WDACApp {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$TimeDetected,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FirstDetectedPath,
        $FirstDetectedUser,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$FirstDetectedProcessID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FirstDetectedProcessName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256AuthenticodeHash,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$OriginDevice,
        $EventType,
        $SigningScenario,
        $OriginalFileName,
        $FileVersion,
        $InternalName,
        $FileDescription,
        $ProductName,
        $PackageFamilyName,
        [bool]$UserWriteable=$false,
        [bool]$FailedWHQL=$false,
        $RequestedSigningLevel,
        $ValidatedSigningLevel,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$BlockingPolicyID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$AppIndex,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        #$Connection.
        #$Transaction = $Connection.BeginTransaction() #FIXME
        $Command = $Connection.CreateCommand()
        #$Transaction = $Connection.BeginTransaction()
        $Command.Commandtext = "INSERT INTO apps (SHA256FlatHash,FileName,TimeDetected,FirstDetectedPath,FirstDetectedUser,FirstDetectedProcessID,FirstDetectedProcessName,SHA256AuthenticodeHash,OriginDevice,EventType,SigningScenario,OriginalFileName,FileVersion,InternalName,FileDescription,ProductName,PackageFamilyName,UserWriteable,FailedWHQL,RequestedSigningLevel,ValidatedSigningLevel,BlockingPolicyID,AppIndex) VALUES (@SHA256FlatHash,@FileName,@TimeDetected,@FirstDetectedPath,@FirstDetectedUser,@FirstDetectedProcessID,@FirstDetectedProcessName,@SHA256AuthenticodeHash,@OriginDevice,@EventType,@SigningScenario,@OriginalFileName,@FileVersion,@InternalName,@FileDescription,@ProductName,@PackageFamilyName,@UserWriteable,@FailedWHQL,@RequestedSigningLevel,@ValidatedSigningLevel,@BlockingPolicyID,@AppIndex)"
            $Command.Parameters.AddWithValue("SHA256FlatHash",$SHA256FlatHash) | Out-Null
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
            $Command.Parameters.AddWithValue("TimeDetected",$TimeDetected) | Out-Null
            $Command.Parameters.AddWithValue("FirstDetectedPath",$FirstDetectedPath) | Out-Null
            $Command.Parameters.AddWithValue("FirstDetectedUser",$FirstDetectedUser) | Out-Null
            $Command.Parameters.AddWithValue("FirstDetectedProcessID",$FirstDetectedProcessID) | Out-Null
            $Command.Parameters.AddWithValue("FirstDetectedProcessName",$FirstDetectedProcessName) | Out-Null
            $Command.Parameters.AddWithValue("SHA256AuthenticodeHash",$SHA256AuthenticodeHash) | Out-Null
            $Command.Parameters.AddWithValue("OriginDevice",$OriginDevice) | Out-Null
            $Command.Parameters.AddWithValue("EventType",$EventType) | Out-Null
            $Command.Parameters.AddWithValue("SigningScenario",$SigningScenario) | Out-Null
            $Command.Parameters.AddWithValue("OriginalFileName",$OriginalFileName) | Out-Null
            $Command.Parameters.AddWithValue("FileVersion",$FileVersion) | Out-Null
            $Command.Parameters.AddWithValue("InternalName",$InternalName) | Out-Null
            $Command.Parameters.AddWithValue("FileDescription",$FileDescription) | Out-Null
            $Command.Parameters.AddWithValue("ProductName",$ProductName) | Out-Null
            $Command.Parameters.AddWithValue("PackageFamilyName",$PackageFamilyName) | Out-Null
            $Command.Parameters.AddWithValue("UserWriteable",$UserWriteable) | Out-Null
            $Command.Parameters.AddWithValue("FailedWHQL",$FailedWHQL) | Out-Null
            $Command.Parameters.AddWithValue("RequestedSigningLevel",$RequestedSigningLevel) | Out-Null
            $Command.Parameters.AddWithValue("ValidatedSigningLevel",$ValidatedSigningLevel) | Out-Null
            $Command.Parameters.AddWithValue("BlockingPolicyID",$BlockingPolicyID) | Out-Null
            $Command.Parameters.AddWithValue("AppIndex",$AppIndex) | Out-Null
        $Command.ExecuteNonQuery()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        # if ($Transaction) {
        #     $Transaction.Rollback()
        # }
        throw $theError
    }
}

function Remove-WDACApp {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.CommandText = "PRAGMA foreign_keys=ON;"
        $Command.Commandtext += "DELETE FROM apps WHERE SHA256FlatHash = @SHA256FlatHash"
        $Command.Parameters.AddWithValue("SHA256FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
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

function Find-WDACCertificate {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$TBSHash,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from certificates WHERE TBSHash = @TBSHash"
        $Command.Parameters.AddWithValue("TBSHash",$TBSHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Get-WDACCertificate {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$TBSHash,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from certificates WHERE TBSHash = @TBSHash"
        $Command.Parameters.AddWithValue("TBSHash",$TBSHash) | Out-Null
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

function Add-WDACCertificate {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$TBSHash,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$CommonName,
        [bool]$IsLeaf=$false,
        $ParentCertTBSHash,
        $NotValidBefore,
        $NotValidAfter,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO certificates (TBSHash,CommonName,IsLeaf,ParentCertTBSHash,NotValidBefore,NotValidAfter) values (@TBSHash,@CommonName,@IsLeaf,@ParentCertTBSHash,@NotValidBefore,@NotValidAfter)"
            $Command.Parameters.AddWithValue("TBSHash",$TBSHash) | Out-Null
            $Command.Parameters.AddWithValue("CommonName",$CommonName) | Out-Null
            $Command.Parameters.AddWithValue("IsLeaf",$IsLeaf) | Out-Null
            $Command.Parameters.AddWithValue("ParentCertTBSHash",$ParentCertTBSHash) | Out-Null
            $Command.Parameters.AddWithValue("NotValidBefore",$NotValidBefore) | Out-Null
            $Command.Parameters.AddWithValue("NotValidAfter",$NotValidAfter) | Out-Null
        $Command.ExecuteNonQuery()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        throw $_
    }

}

function Add-WDACAppSigner {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$AppIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$SignatureIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$CertificateTBSHash,
        $SignatureType,
        [bool]$PageHash = $false,
        [int]$Flags,
        [int]$PolicyBits,
        $ValidatedSigningLevel,
        $VerificationError,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO signers (AppIndex,SignatureIndex,CertificateTBSHash,SignatureType,PageHash,Flags,PolicyBits,ValidatedSigningLevel,VerificationError) values (@AppIndex,@SignatureIndex,@CertificateTBSHash,@SignatureType,@PageHash,@Flags,@PolicyBits,@ValidatedSigningLevel,@VerificationError)"
            $Command.Parameters.AddWithValue("AppIndex",$AppIndex) | Out-Null
            $Command.Parameters.AddWithValue("SignatureIndex",$SignatureIndex) | Out-Null
            $Command.Parameters.AddWithValue("CertificateTBSHash",$CertificateTBSHash) | Out-Null
            $Command.Parameters.AddWithValue("SignatureType",$SignatureType) | Out-Null
            $Command.Parameters.AddWithValue("PageHash",$PageHash) | Out-Null
            $Command.Parameters.AddWithValue("Flags",$Flags) | Out-Null
            $Command.Parameters.AddWithValue("PolicyBits",$PolicyBits) | Out-Null
            $Command.Parameters.AddWithValue("ValidatedSigningLevel",$ValidatedSigningLevel) | Out-Null
            $Command.Parameters.AddWithValue("VerificationError",$VerificationError) | Out-Null
        $Command.ExecuteNonQuery()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        throw $_
    }
}

function Find-WDACPolicy {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $result
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $_
    }
}

function Find-WDACPolicyByName {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from policies WHERE PolicyName = @PolicyName"
        $Command.Parameters.AddWithValue("PolicyName",$PolicyName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $result
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $_
    }
}

function Find-WDACPolicyByID {
#Note: This is not PolicyGUID. PolicyGUID is the primary key of the table while PolicyID is not.
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyID,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from policies WHERE PolicyID = @PolicyID"
        $Command.Parameters.AddWithValue("PolicyID",$PolicyID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $result
    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $_
    }
}

function Add-WDACPolicy {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        $PolicyID,
        $PolicyHash,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $PolicyVersion,
        $ParentPolicyGUID,
        [bool]$BaseOrSupplemental,
        [bool]$IsSigned,
        [bool]$AuditMode,
        [bool]$IsPillar,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $OriginLocation,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $OriginLocationType,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO policies (PolicyGUID,PolicyID,PolicyHash,PolicyName,PolicyVersion,ParentPolicyGUID,BaseOrSupplemental,IsSigned,AuditMode,IsPillar,OriginLocation,OriginLocationType) values (@PolicyGUID,@PolicyID,@PolicyHash,@PolicyName,@PolicyVersion,@ParentPolicyGUID,@BaseOrSupplemental,@IsSigned,@AuditMode,@IsPillar,@OriginLocation,@OriginLocationType)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            $Command.Parameters.AddWithValue("PolicyID",$PolicyID) | Out-Null
            $Command.Parameters.AddWithValue("PolicyHash",$PolicyHash) | Out-Null
            $Command.Parameters.AddWithValue("PolicyName",$PolicyName) | Out-Null
            $Command.Parameters.AddWithValue("PolicyVersion",$PolicyVersion) | Out-Null
            $Command.Parameters.AddWithValue("ParentPolicyGUID",$ParentPolicyGUID) | Out-Null
            $Command.Parameters.AddWithValue("BaseOrSupplemental",$BaseOrSupplemental) | Out-Null
            $Command.Parameters.AddWithValue("IsSigned",$IsSigned) | Out-Null
            $Command.Parameters.AddWithValue("AuditMode",$AuditMode) | Out-Null
            $Command.Parameters.AddWithValue("IsPillar",$IsPillar) | Out-Null
            $Command.Parameters.AddWithValue("OriginLocation",$OriginLocation) | Out-Null
            $Command.Parameters.AddWithValue("OriginLocationType",$OriginLocationType) | Out-Null
            
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

function Get-WDACPolicy {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    PolicyGUID = $Reader["PolicyGUID"];
                    PolicyID = $Reader["PolicyID"];
                    PolicyHash = $Reader["PolicyHash"];
                    PolicyName = $Reader["PolicyName"];
                    PolicyVersion = $Reader["PolicyVersion"];
                    ParentPolicyGUID = $Reader["ParentPolicyGUID"];
                    BaseOrSupplemental = [bool]$Reader["BaseOrSupplemental"];
                    IsSigned = [bool]$Reader["IsSigned"];
                    AuditMode = [bool]$Reader["AuditMode"];
                    IsPillar = [bool]$Reader["IsPillar"];
                    OriginLocation = $Reader["OriginLocation"];
                    OriginLocationType = $Reader["OriginLocationType"]
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

function Get-WDACPoliciesGUIDandName {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "SELECT PolicyGUID,PolicyName From policies;"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
                    PolicyGUID = $Reader["PolicyGUID"];
                    PolicyName = $Reader["PolicyName"]
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

function Get-WDACPublisher {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$LeafCertCN,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PcaCertTBSHash,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from publishers WHERE LeafCertCN = @LeafCertCN AND PcaCertTBSHash = @PcaCertTBSHash"
        $Command.Parameters.AddWithValue("LeafCertCN",$LeafCertCN) | Out-Null
        $Command.Parameters.AddWithValue("PcaCertTBSHash",$PcaCertTBSHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
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

function Get-WDACPublisherByPublisherIndex {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from publishers WHERE PublisherIndex = @PublisherIndex"
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
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

function Add-WDACPublisher {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$LeafCertCN,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PcaCertTBSHash,
        [bool]$Untrusted = $false,
        [bool]$TrustedDriver = $false,
        [bool]$TrustedUserMode = $false,
        [bool]$Staged = $false,
        [bool]$Revoked = $false,
        [bool]$Deferred = $false,
        [bool]$Blocked = $false,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PublisherTBSHash,
        $AllowedPolicyID,
        $DeferredPolicyIndex,
        $Comment,
        $BlockingPolicyID,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO publishers (LeafCertCN,PcaCertTBSHash,Untrusted,TrustedDriver,TrustedUserMode,Staged,Revoked,Deferred,Blocked,PublisherTBSHash,AllowedPolicyID,DeferredPolicyIndex,Comment,BlockingPolicyID,PublisherIndex) values (@LeafCertCN,@PcaCertTBSHash,@Untrusted,@TrustedDriver,@TrustedUserMode,@Staged,@Revoked,@Deferred,@Blocked,@PublisherTBSHash,@AllowedPolicyID,@DeferredPolicyIndex,@Comment,@BlockingPolicyID,(SELECT IFNULL(Max(PublisherIndex), 0) + 1 FROM publishers))"
            $Command.Parameters.AddWithValue("LeafCertCN",$LeafCertCN) | Out-Null
            $Command.Parameters.AddWithValue("PcaCertTBSHash",$PcaCertTBSHash) | Out-Null
            $Command.Parameters.AddWithValue("Untrusted",$Untrusted) | Out-Null
            $Command.Parameters.AddWithValue("TrustedDriver",$TrustedDriver) | Out-Null
            $Command.Parameters.AddWithValue("TrustedUserMode",$TrustedUserMode) | Out-Null
            $Command.Parameters.AddWithValue("Staged",$Staged) | Out-Null
            $Command.Parameters.AddWithValue("Revoked",$Revoked) | Out-Null
            $Command.Parameters.AddWithValue("Deferred",$Deferred) | Out-Null
            $Command.Parameters.AddWithValue("Blocked",$Blocked) | Out-Null
            $Command.Parameters.AddWithValue("PublisherTBSHash",$PublisherTBSHash) | Out-Null
            $Command.Parameters.AddWithValue("AllowedPolicyID",$AllowedPolicyID) | Out-Null
            $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
            $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
            $Command.Parameters.AddWithValue("BlockingPolicyID",$BlockingPolicyID) | Out-Null
            
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

function Get-WDACFilePublishers {
#Gets Multiple File Publishers!
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PublisherIndex,
        $FileName,
        $MinimumAllowedVersion,
        $MaximumAllowedVersion,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $null
    $NoConnectionProvided = $false

    try {
        if ($SpecificFileNameLevel) {
            $SpecificFileNameLevel = [string]$SpecificFileNameLevel
        }

        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($FileName) {
            $Command.Commandtext = "Select * from file_publishers WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        } else {
            $Command.Commandtext = "Select * from file_publishers WHERE PublisherIndex = @PublisherIndex AND SpecificFileNameLevel = @SpecificFileNameLevel"
        }
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        if ($Reader.HasRows) {
            $result = @()
        }
        while($Reader.HasRows) {
            if($Reader.Read()) {
                
                $VersionNumMin = $Reader["MinimumAllowedVersion"];
                $VersionNumMinTmp = $VersionNumMin
                $VersionNumMax = $Reader["MaximumAllowedVersion"];
                $VersionNumMaxTmp = $VersionNumMax
                if (-not $VersionNumMin) {
                    $VersionNumMin = "0.0.0.0"
                }
                if (-not $VersionNumMax) {
                    $VersionNumMax = "65535.65535.65535.65535"
                }

                if ($MinimumAllowedVersion) {
                    if ((Compare-Versions -Version1 $VersionNumMax -Version2 $MinimumAllowedVersion) -eq -1) {
                        continue;
                    }
                    if ((Compare-Versions -Version1 $MinimumAllowedVersion -Version2 $VersionNumMin) -eq 1) {
                        continue;
                    }
                } 
                if ($MaximumAllowedVersion) {
                    if ((Compare-Versions -Version1 $VersionNumMin -Version2 $MaximumAllowedVersion) -eq 1) {
                        continue;
                    }
                    if ((Compare-Versions -Version1 $MaximumAllowedVersion -Version2 $VersionNumMax) -eq -1) {
                        continue;
                    }  
                }

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

function Add-WDACFilePublisher {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PublisherIndex,
        [bool]$Untrusted = $false,
        [bool]$TrustedDriver = $false,
        [bool]$TrustedUserMode = $false,
        [bool]$Staged = $false,
        [bool]$Revoked = $false,
        [bool]$Deferred = $false,
        [bool]$Blocked = $false,
        $AllowedPolicyID,
        $DeferredPolicyIndex,
        $Comment,
        $BlockingPolicyID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$MinimumAllowedVersion,
        $MaximumAllowedVersion="65535.65535.65535.65535",
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO file_publishers (PublisherIndex,Untrusted,TrustedDriver,TrustedUserMode,Staged,Revoked,Deferred,Blocked,AllowedPolicyID,DeferredPolicyIndex,Comment,BlockingPolicyID,MinimumAllowedVersion,MaximumAllowedVersion,FileName,SpecificFileNameLevel) values (@PublisherIndex,@Untrusted,@TrustedDriver,@TrustedUserMode,@Staged,@Revoked,@Deferred,@Blocked,@AllowedPolicyID,@DeferredPolicyIndex,@Comment,@BlockingPolicyID,@MinimumAllowedVersion,@MaximumAllowedVersion,@FileName,@SpecificFileNameLevel)"
            $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
            $Command.Parameters.AddWithValue("Untrusted",$Untrusted) | Out-Null
            $Command.Parameters.AddWithValue("TrustedDriver",$TrustedDriver) | Out-Null
            $Command.Parameters.AddWithValue("TrustedUserMode",$TrustedUserMode) | Out-Null
            $Command.Parameters.AddWithValue("Staged",$Staged) | Out-Null
            $Command.Parameters.AddWithValue("Revoked",$Revoked) | Out-Null
            $Command.Parameters.AddWithValue("Deferred",$Deferred) | Out-Null
            $Command.Parameters.AddWithValue("Blocked",$Blocked) | Out-Null
            $Command.Parameters.AddWithValue("AllowedPolicyID",$AllowedPolicyID) | Out-Null
            $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
            $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
            $Command.Parameters.AddWithValue("BlockingPolicyID",$BlockingPolicyID) | Out-Null
            $Command.Parameters.AddWithValue("MinimumAllowedVersion",$MinimumAllowedVersion) | Out-Null
            $Command.Parameters.AddWithValue("MaximumAllowedVersion",$MaximumAllowedVersion) | Out-Null
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

function Set-WDACFilePublisherMinimumAllowedVersion {
#Note, this function only works if just ONE file publisher rule exists for the publisher index / filename / filenamelevel combination.
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PublisherIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $MinimumAllowedVersion,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        
        $tempFilePublishers = Get-WDACFilePublishers -PublisherIndex $PublisherIndex -FileName $FileName -MinimumAllowedVersion "0.0.0.0" -SpecificFileNameLevel $SpecificFileNameLevel -ErrorAction Stop
        
        if ($tempFilePublishers.Count -gt 1) {
            throw "Cannot decide which file publisher rule to set MinimumAllowedVersion, as there are multiple which fit the specified criteria."
        }

        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "UPDATE file_publishers SET MinimumAllowedVersion = @MinimumAllowedVersion WHERE PublisherIndex = @PublisherIndex AND SpecificFileNameLevel = @SpecificFileNameLevel AND FileName = @FileName"
            $Command.Parameters.AddWithValue("MinimumAllowedVersion",$MinimumAllowedVersion) | Out-Null
            $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
            $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
           
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

function Get-WDACDevice {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from devices WHERE DeviceName = @DeviceName"
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    DeviceName = $Reader["DeviceName"];
                    AllowedGroup = $Reader["AllowedGroup"];
                    UpdateDeferring = [bool]$Reader["UpdateDeferring"];
                    DeferredPolicyIndex = $Reader["DeferredPolicyIndex"]
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

function Add-WDACDevice {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$AllowedGroup,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO devices (DeviceName,AllowedGroup) values (@DeviceName,@AllowedGroup)"
            $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
            $Command.Parameters.AddWithValue("AllowedGroup",$AllowedGroup) | Out-Null
           
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

function Add-WDACPolicyAssignment {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO policy_assignments (GroupName,PolicyGUID) values (@GroupName,@PolicyGUID)"
            $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            
            
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

function Expand-WDACAppDeprecated {
#NOTE: This function also adds publishers and file publishers to the database!
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [ValidateNotNullOrEmpty()]
        [string]$MinimumAllowedVersion,
        [ValidateNotNullOrEmpty()]
        [string]$MaximumAllowedVersion,
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [switch]$AlwaysSetMinimumVersions,
        [switch]$AddFilePublisher,
        [switch]$AddPublisher
    )

    if ($AddFilePublisher) {
    #If we want to add a file publisher to the database, we will need to add the publisher as well
        $AddPublisher = $true
    }

    try {

        $TempApp = Get-WDACApp -SHA256FlatHash $SHA256FlatHash -ErrorAction Stop

        $FileVersion = $null
        if ($TempApp.FileVersion) {
            $FileVersion = $TempApp.FileVersion
        }

        if (-not $FileName) {        
            if ($TempApp.$SpecificFileNameLevel) {
                $FileName = $TempApp.$SpecificFileNameLevel
            } 
        }

        $Signers = Get-WDACAppSignersByFlatHash -SHA256FlatHash $SHA256FlatHash -ErrorAction Stop
        if (-not $Signers) {
            return $null
        }
    
        $Levels = @("Publisher", "FilePublisher", "LeafCertificate", "PcaCertificate")
        
        $Result = [PSCustomObject]@{}
        foreach ($LevelType in $Levels) {
            $Result | Add-Member -Type NoteProperty -Name $LevelType -Value $null
        }
        $Publishers = @()
        $FilePublishers = @()
        $LeafCertificates = @()
        $PcaCertificates = @()
    
        foreach ($Signer in $Signers) {
            $LeafCertTBSHash = $Signer.CertificateTBSHash
            $LeafCert = Get-WDACCertificate -TBSHash $LeafCertTBSHash -ErrorAction Stop
            $LeafCertificates += $LeafCert
            if ($LeafCert.ParentCertTBSHash) {
                $PcaCert = Get-WDACCertificate -TBSHash $LeafCert.ParentCertTBSHash -ErrorAction Stop
                $PcaCertificates += $PcaCert

                $Publisher = Get-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -ErrorAction Stop
                if (-not $Publisher -and $AddPublisher) {
                #If publisher isn't in the database, then add it--but only if those are specified levels the user wants
                    if (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -PublisherTBSHash $LeafCertTBSHash -ErrorAction Stop) {
                        $Publisher = Get-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -ErrorAction Stop
                    } else {
                        throw "Trouble adding a publisher to the database."
                    }
                }
                $Publishers += $Publisher
            }
    
            if ($FileVersion -and $FileName) {
            #Can only get file publishers for this app if there is a file version and file name set

                
                $FilePublishers2 = Get-WDACFilePublishers -PublisherIndex $Publisher.PublisherIndex -FileName $FileName -MinimumAllowedVersion:$MinimumAllowedVersion -MaximumAllowedVersion:$MaximumAllowedVersion -SpecificFileNameLevel $SpecificFileNameLevel -ErrorAction Stop
                
                if ($AlwaysSetMinimumVersions -and (-not $MinimumAllowedVersion -or ($MinimumAllowedVersion -eq "0.0.0.0"))) {
                #Add new file publisher to the database if AlwaysSetMinimumVersions is set
                #If minimum version is specified in the search, don't bother adding a file publisher or modifying a file publisher entry to have a lower version number--but this can be overriden if it was 0.0.0.0
                    
                    if ($FilePublishers2.Count -eq 1) {
                        $thisFilePublisher = $FilePublishers2[0]
                        if ((Compare-Versions -Version1 $FileVersion -Version2 $thisFilePublisher.MinimumAllowedVersion) -eq -1) {
                            
                            Set-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $Publisher -FileName $FileName -MinimumAllowedVersion $FileVersion -SpecificFileNameLevel $SpecificFileNameLevel -ErrorAction Stop
                        }
                    } elseif ($FilePublishers2.Count -gt 1) {
                        throw "AlwaysSetMinimumVersions is set, but multiple file publishers encountered for one signer / app combination."
                    } else {
                        if ($AddFilePublisher) {
                        #Only add FilePublisher to the database if that is specified
                            
                            Add-WDACFilePublisher -MinimumAllowedVersion $FileVersion -PublisherIndex $Publisher.PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -ErrorAction Stop
                        }
                    }

                    $FilePublishers2 = Get-WDACFilePublishers -PublisherIndex $Publisher.PublisherIndex -FileName $FileName -MinimumAllowedVersion:$MinimumAllowedVersion -MaximumAllowedVersion:$MaximumAllowedVersion -SpecificFileNameLevel $SpecificFileNameLevel -ErrorAction Stop
                }
                
                if ($FilePublishers2) {
                    $FilePublishers += $FilePublishers2
                }
            }
        }

        foreach ($LevelType in $Levels) {
            if ($LevelType -eq "Publisher") {
                $Result.Publisher = $Publishers
            } elseif ($LevelType -eq "FilePublisher") {
                $Result.FilePublisher = $FilePublishers
            } elseif ($LevelType -eq "LeafCertificate") {
                $Result.LeafCertificate = $LeafCertificates
            } elseif ($LevelType -eq "PcaCertificate") {
                $Result.PcaCertificate = $PcaCertificates
            }
        }
        
        return $Result
    } catch {
        throw $_
    }
}

function Add-WDACFileName {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [bool]$Untrusted = $false,
        [bool]$TrustedDriver = $false,
        [bool]$TrustedUserMode = $false,
        [bool]$Staged = $false,
        [bool]$Revoked = $false,
        [bool]$Deferred = $false,
        [bool]$Blocked = $false,
        $AllowedPolicyID,
        $DeferredPolicyIndex,
        $Comment,
        $BlockingPolicyID,
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO file_names (FileName,SpecificFileNameLevel,Untrusted,TrustedDriver,TrustedUserMode,Staged,Revoked,Deferred,Blocked,AllowedPolicyID,DeferredPolicyIndex,Comment,BlockingPolicyID) values (@FileName,@SpecificFileNameLevel,@Untrusted,@TrustedDriver,@TrustedUserMode,@Staged,@Revoked,@Deferred,@Blocked,@AllowedPolicyID,@DeferredPolicyIndex,@Comment,@BlockingPolicyID)"
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
            $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
            $Command.Parameters.AddWithValue("Untrusted",$Untrusted) | Out-Null
            $Command.Parameters.AddWithValue("TrustedDriver",$TrustedDriver) | Out-Null
            $Command.Parameters.AddWithValue("TrustedUserMode",$TrustedUserMode) | Out-Null
            $Command.Parameters.AddWithValue("Staged",$Staged) | Out-Null
            $Command.Parameters.AddWithValue("Revoked",$Revoked) | Out-Null
            $Command.Parameters.AddWithValue("Deferred",$Deferred) | Out-Null
            $Command.Parameters.AddWithValue("Blocked",$Blocked) | Out-Null
            $Command.Parameters.AddWithValue("AllowedPolicyID",$AllowedPolicyID) | Out-Null
            $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
            $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
            $Command.Parameters.AddWithValue("BlockingPolicyID",$BlockingPolicyID) | Out-Null
            
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

function Get-WDACFileName {
    [CmdletBinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        [ValidateNotNullOrEmpty()]
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
        $Command.Commandtext = "Select * from file_names WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
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

function Expand-WDACApp {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [switch]$AddPublisher
    )

    $Result = @()
    try {
        $Signers = Get-WDACAppSignersByFlatHash -SHA256FlatHash $SHA256FlatHash -ErrorAction Stop
        if (-not $Signers) {
            return $null
        }

        foreach ($Signer in $Signers) {
            $LeafCertTBSHash = $Signer.CertificateTBSHash
            $LeafCert = Get-WDACCertificate -TBSHash $LeafCertTBSHash -ErrorAction Stop

            if ($LeafCert.ParentCertTBSHash) {
                $PcaCert = Get-WDACCertificate -TBSHash $LeafCert.ParentCertTBSHash -ErrorAction Stop
                $Publisher = Get-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -ErrorAction Stop
                if (-not $Publisher -and $AddPublisher) {
                #If publisher isn't in the database, then add it--but only if those are specified levels the user wants
                    if (-not (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -PublisherTBSHash $LeafCertTBSHash -ErrorAction Stop)) {
                        throw "Trouble adding a publisher to the database."
                    }
                }
            }

            $Result += @{SignatureIndex = $Signer.SignatureIndex; SignerInfo = ( $Signer | Select-Object SignatureType,PageHash,Flags,PolicyBits,ValidatedSigningLevel,VerificationError); LeafCert = $LeafCert; PcaCert = $PcaCert}
        }

        $ResultObj = $Result | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }
        return $ResultObj
    } catch {
        throw $_
    }
}

function Get-AppTrusted {
#Determines if an app (WDAC event) would be able to run based on the "TrustedDriver" or "TrustedUserMode" attributes of various rule levels
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Hash","FlatHash")]
        [string]$SHA256FlatHash,
        [Alias("Levels")]
        [ValidateSet("Hash","Publisher","FilePublisher","LeafCertificate","PcaCertificate","FilePath","FileName")]
        $AllPossibleLevels,
        [switch]$Driver,
        [switch]$UserMode
    )

    if (-not $AllPossibleLevels) {
        $AllPossibleLevels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    }
    $SpecificFileNameLevels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")

    try {
        $AppInstance = Get-WDACApp -SHA256FlatHash $SHA256FlatHash -ErrorAction Stop
        if (-not $AppInstance) {
            throw "No instance of this app $SHA256FlatHash in the database."
        }
        #TODO -> MSI_OR_SCRIPT APP INSTANCE
        $CertInfo = Expand-WDACApp -SHA256FlatHash $SHA256FlatHash -ErrorAction Stop

        if (-not $Driver -and -not $UserMode) {
            if ($AppInstance.SigningScenario -eq "UserMode") {
                $UserMode = $true
            } elseif ($AppInstance.SigningScenario -eq "Driver") {
                $Driver = $true
            } else {
                $UserMode = $true
                $Driver = $false
            }
        }

        function Get-TrustedInstance {
            [CmdletBinding()]
            Param (
                [ValidateNotNullOrEmpty()]
                [Parameter(Mandatory=$true)]
                $Instance,
                [switch]$Driver,
                [switch]$UserMode
            )
    
            if ($Driver -and $UserMode -and ($Instance.TrustedDriver -and $Instance.TrustedUserMode)) {
                return $true
            } elseif ($Driver -and $Instance.TrustedDriver) {
                return $true
            } elseif ($UserMode -and $Instance.TrustedUserMode) {
                return $true
            }
        }

        function Get-TrustedInstanceFilePublishers {
            [CmdletBinding()]
            Param (
                [ValidateNotNullOrEmpty()]
                [Parameter(Mandatory=$true)]
                $FilePublishers,
                [switch]$Driver,
                [switch]$UserMode,
                [ValidateNotNullOrEmpty()]
                [Parameter(Mandatory=$true)]
                $FileVersion
            )

            foreach ($FilePublisher in $FilePublishers) {
                $CompareMin = Compare-Versions -Version1 $FileVersion -Version2 $FilePublisher.MinimumAllowedVersion
                $CompareMax = Compare-Versions -Version1 $FileVersion -Version2 $FilePublisher.MaximumAllowedVersion
                $Encompasses = $false
                if (($CompareMin -eq 1 -or $CompareMin -eq 0) -and ($CompareMax -eq -1 -or $CompareMax -eq 0)) {
                    $Encompasses = $true
                }

                if ($Encompasses -and (Get-TrustedInstance -Instance $FilePublisher -Driver:$Driver -UserMode:$UserMode)) {
                    return $true
                }
            }
        }

        switch ($AllPossibleLevels) {
            "Hash" {
                if (Get-TrustedInstance -Instance $AppInstance -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                    return $true
                }
            }
            "FilePath" {<#TODO#>}
            "FileName" {
                if ($AppInstance.OriginalFileName -or $AppInstance.InternalName -or $AppInstance.FileDescription -or $AppInstance.ProductName -or $AppInstance.PackageFamilyName) {
                    switch ($SpecificFileNameLevels) {
                        "OriginalFileName" {
                            if ($AppInstance.OriginalFileName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.OriginalFileName
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "InternalName" {
                            if ($AppInstance.InternalName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.InternalName -SpecificFileNameLevel "InternalName"
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "FileDescription" {
                            if ($AppInstance.FileDescription) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.FileDescription -SpecificFileNameLevel "FileDescription"
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "ProductName" {
                            if ($AppInstance.ProductName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.ProductName -SpecificFileNameLevel "ProductName"
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "PackageFamilyName" {
                            if ($AppInstance.PackageFamilyName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.PackageFamilyName -SpecificFileNameLevel "PackageFamilyName"
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                    }
                } 
            }
            "LeafCertificate" {
                if ($CertInfo) {
                    foreach ($LeafCertificate in $CertInfo.LeafCert) {
                        if (Get-TrustedInstance -Instance $LeafCertificate -Driver:$Driver -UserMode:$UserMode) {
                            return $true
                        }
                    }
                }
            }
            "PcaCertificate" {
                if ($CertInfo) {
                    foreach ($PcaCertificate in $CertInfo.PcaCert) {
                        if (Get-TrustedInstance -Instance $PcaCertificate -Driver:$Driver -UserMode:$UserMode) {
                            return $true
                        }
                    }
                }
            }
            "Publisher" {
                if ($CertInfo) {
                    foreach ($LeafCertificate in $CertInfo.LeafCert) {
                        if ($LeafCertificate.CommonName -and $LeafCertificate.ParentCertTBSHash) {
                            $TempPublisher = Get-WDACPublisher -LeafCertCN $LeafCertificate.CommonName -PcaCertTBSHash $LeafCertificate.ParentCertTBSHash
                            if ($TempPublisher) {
                                if (Get-TrustedInstance -Instance $TempPublisher -Driver:$Driver -UserMode:$UserMode) {
                                    return $true
                                }
                            }
                        }
                    }
                }
            }
            "FilePublisher" {
                if ($CertInfo -and $AppInstance.FileVersion -and ($AppInstance.OriginalFileName -or $AppInstance.InternalName -or $AppInstance.FileDescription -or $AppInstance.ProductName -or $AppInstance.PackageFamilyName)) {
                    foreach ($LeafCertificate in $CertInfo.LeafCert) {
                        if ($LeafCertificate.CommonName -and $LeafCertificate.ParentCertTBSHash) {
                            $TempPublisher = Get-WDACPublisher -LeafCertCN $LeafCertificate.CommonName -PcaCertTBSHash $LeafCertificate.ParentCertTBSHash
                            if ($TempPublisher.PublisherIndex) {
                                switch ($SpecificFileNameLevels) {
                                    "OriginalFileName" {
                                        if ($AppInstance.OriginalFileName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.OriginalFileName -SpecificFileNameLevel "OriginalFileName"
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "InternalName" {
                                        if ($AppInstance.InternalName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.InternalName -SpecificFileNameLevel "InternalName"
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "FileDescription" {
                                        if ($AppInstance.FileDescription) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.FileDescription -SpecificFileNameLevel "FileDescription"
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "ProductName" {
                                        if ($AppInstance.ProductName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.ProductName -SpecificFileNameLevel "ProductName"
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "PackageFamilyName" {
                                        if ($AppInstance.PackageFamilyName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.PackageFamilyName -SpecificFileNameLevel "PackageFamilyName"
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return $false
    } catch {
        throw $_
    }
}