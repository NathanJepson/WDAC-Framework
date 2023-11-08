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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\File-Publisher-Helpers.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\File-Publisher-Helpers.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\File-Publisher-Helpers.psm1")
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

function Test-VersionEncompassed {
#Uses a less-than or equal to and greater-than-or-equal-to relationship
    [cmdletbinding()]
    param (
        [Alias("Version")]
        $VersionToCheck,
        [Alias("Min","Minimum")]
        $MinimumVersion,
        [Alias("Max","Maximum")]
        $MaximumVersion
    )

    $CompareMin = Compare-Versions -Version1 $VersionToCheck -Version2 $MinimumVersion
    $CompareMax = Compare-Versions -Version1 $VersionToCheck -Version2 $MaximumVersion
    $Encompasses = $false
    if (($CompareMin -eq 1 -or $CompareMin -eq 0) -and ($CompareMax -eq -1 -or $CompareMax -eq 0)) {
        $Encompasses = $true
    }

    return $Encompasses
}

function Set-IncrementVersionNumber {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Version")]
        $VersionNumber
    )

    $VersionSplit = $VersionNumber -split "\."
    $VersionSplit[-1] = ([int]$VersionSplit[-1]) + 1
    for ($i=-1; $i -gt ((-1) * ($VersionSplit.Count + 1)); $i--) {
        if ([int]$VersionSplit[$i] -ge 65536) {
            if (-not ($i -eq -4)) {
                $VersionSplit[$i] = 0
                $VersionSplit[$i-1] = ([int]$VersionSplit[$i-1]) + 1
            } else {
                #Note: Version Number of 65535.65535.65535.65535 wraps back around to 0.0.0.0
                return "0.0.0.0"
            }
        }
    }

    return ($VersionSplit -Join ".")
}

function Format-SQLResult {
#This converts all PSObject members of type [System.DBNull] to $null
    [cmdletbinding()]
    Param (
        $Object
    )

    if (($null -eq $Object) -or ($Object -is [System.DBNull])) {
        return $null
    }

    $Object = [PSCustomObject[]]$Object

    for ($i=0; $i -lt $Object.Count; $i++) {
        foreach ($Property in $Object[$i].PSObject.Properties) {
            if ($Property.TypeNameOfValue -eq [System.DBNull]) {
                $Object[$i].($Property.Name) = $null
            }
        }
    }
    
    return $Object
}

function Find-WDACGroup {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $GroupName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
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

function New-WDACGroup_SQL {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $GroupName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO GROUPS (GroupName) VALUES (@GroupName)"
        $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
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

function Get-WDACGroups {
    [cmdletbinding()]
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
        $Command.Commandtext = "SELECT GroupName From groups;"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Find-WDACGroupMirror {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $GroupName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $MirroredGroupName,
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
        $Command.Commandtext = "Select * from group_mirrors WHERE GroupName = @GroupName AND MirroredGroupName = @MirroredGroupName"
        $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
        $Command.Parameters.AddWithValue("MirroredGroupName",$MirroredGroupName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Add-WDACGroupMirror {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $GroupName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $MirroredGroupName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO group_mirrors (GroupName,MirroredGroupName) VALUES (@GroupName,@MirroredGroupName)"
        $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
        $Command.Parameters.AddWithValue("MirroredGroupName",$MirroredGroupName) | Out-Null
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

function Get-MAXAppIndexID {
    [cmdletbinding()]
    Param ( 
        [switch]$isMSIorScript,
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
                    if ($NoConnectionProvided -and $Connection) {
                        $Connection.close()
                    }
                    return $null
                } else {
                    $Reader.Close()
                    if ($NoConnectionProvided -and $Connection) {
                        $Connection.close()
                    }
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

function Find-MSIorScript {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
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
        $Command.Commandtext = "Select * from msi_or_script WHERE SHA256FlatHash = @FlatHash"
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

function Get-MSIorScriptAllHashes {
    [cmdletbinding()]
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
        $Command.Commandtext = "Select * from msi_or_script"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
                    SHA256FlatHash = $Reader["SHA256FlatHash"];
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

function Get-MSIorScriptSkippedStatus {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    $result = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select Skipped from msi_or_script WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                if ($Reader["Skipped"]) {
                    if ( ([bool]$Reader["Skipped"])) {
                        $result = $true
                    } else {
                        $result = $false
                    }
                } else {
                    $result = $false
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

function Get-MSIorScriptUntrustedStatus {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    $result = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select Untrusted from msi_or_script WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                if ($Reader["Untrusted"]) {
                    if ( ([bool]$Reader["Untrusted"])) {
                        $result = $true
                    } else {
                        $result = $false
                    }
                } else {
                    $result = $false
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

function Find-WDACApp {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
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

function Get-WDACAppsAllHashes {
    [cmdletbinding()]
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
        $Command.Commandtext = "Select * from apps"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
                    SHA256FlatHash = $Reader["SHA256FlatHash"];
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

function Get-WDACAppSigners {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$AppIndex,
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

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Get-WDACAppSignersByFlatHash {
    [cmdletbinding()]
    param(
        [string]$SHA256FlatHash,
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
        $Command.Commandtext = "SELECT * From signers WHERE AppIndex = (SELECT AppIndex from apps WHERE SHA256FlatHash = @SHA256FlatHash);"
        $Command.Parameters.AddWithValue("SHA256FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Get-WDACAppsToSetTrust {
    [cmdletbinding()]
    param(
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

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Get-WDACAppSigningScenario {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
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
        $Command.Commandtext = "Select SigningScenario from apps WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                if ($Reader["SigningScenario"]) {
                    $result = $Reader["SigningScenario"]
                } else {
                    $result = $null
                }
            }
        }
        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($result -is [System.DBNull]) {
            return $null
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

function Get-WDACAppSkippedStatus {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    $result = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select Skipped from apps WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                if ($Reader["Skipped"]) {
                    if ( ([bool]$Reader["Skipped"])) {
                        $result = $true
                    } else {
                        $result = $false
                    }
                } else {
                    $result = $false
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

function Get-WDACAppUntrustedStatus {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    $result = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select Untrusted from apps WHERE SHA256FlatHash = @FlatHash"
        $Command.Parameters.AddWithValue("FlatHash",$SHA256FlatHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                if ($Reader["Untrusted"]) {
                    if ( ([bool]$Reader["Untrusted"])) {
                        $result = $true
                    } else {
                        $result = $false
                    }
                } else {
                    $result = $false
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
            #This PRAGMA is needed so that foreign key constraints will work upon deleting
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
   
        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Get-WDACCertificateCommonName {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$TBSHash,
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
        $Command.Commandtext = "Select CommonName from certificates WHERE TBSHash = @TBSHash"
        $Command.Parameters.AddWithValue("TBSHash",$TBSHash) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    CommonName = $Reader["CommonName"]
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
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        throw $theError
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

        if ($IsSigned) {
            $Command.Commandtext = "INSERT INTO policies (PolicyGUID,PolicyID,PolicyHash,PolicyName,PolicyVersion,ParentPolicyGUID,BaseOrSupplemental,IsSigned,AuditMode,IsPillar,OriginLocation,OriginLocationType,LastSignedVersion) values (@PolicyGUID,@PolicyID,@PolicyHash,@PolicyName,@PolicyVersion,@ParentPolicyGUID,@BaseOrSupplemental,@IsSigned,@AuditMode,@IsPillar,@OriginLocation,@OriginLocationType,@LastSignedVersion)"
            $Command.Parameters.AddWithValue("LastSignedVersion",$PolicyVersion) | Out-Null
        } else {
            $Command.Commandtext = "INSERT INTO policies (PolicyGUID,PolicyID,PolicyHash,PolicyName,PolicyVersion,ParentPolicyGUID,BaseOrSupplemental,IsSigned,AuditMode,IsPillar,OriginLocation,OriginLocationType,LastUnsignedVersion) values (@PolicyGUID,@PolicyID,@PolicyHash,@PolicyName,@PolicyVersion,@ParentPolicyGUID,@BaseOrSupplemental,@IsSigned,@AuditMode,@IsPillar,@OriginLocation,@OriginLocationType,@LastUnsignedVersion)"
            $Command.Parameters.AddWithValue("LastUnsignedVersion",$PolicyVersion) | Out-Null
        }

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

function Get-WDACPolicyVersion {
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
                $result = $Reader["PolicyVersion"]
                break
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($result -is [System.DBNull]) {
            return $null
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

function Set-WDACPolicyVersion {
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
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE policies SET PolicyVersion = @PolicyVersion WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("PolicyVersion",$Version) | Out-Null
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

function Set-WDACPolicyPillar {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Set,
        [switch]$Unset,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if ((-not $Set) -and (-not $Unset)) {
        throw "Set-WDACPolicyPillar function called without setting `"set`" or `"unset`" flags."
    } elseif ($Set -and $Unset) {
        throw "Cannot set both `"set`" and `"unset`" flags for cmdlet Set-WDACPolicyPillar"
    }

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($Set) {
            $Command.Commandtext = "UPDATE policies SET IsPillar = 1 WHERE PolicyGUID = @PolicyGUID"
        } elseif ($Unset) {
            $Command.Commandtext = "UPDATE policies SET IsPillar = 0 WHERE PolicyGUID = @PolicyGUID"
        }
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

function Set-WDACPolicySigned {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Set,
        [switch]$Unset,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if ((-not $Set) -and (-not $Unset)) {
        throw "Set-WDACPolicySigned function called without setting `"set`" or `"unset`" flags."
    } elseif ($Set -and $Unset) {
        throw "Cannot set both `"set`" and `"unset`" flags for cmdlet Set-WDACPolicySigned"
    }

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($Set) {
            $Command.Commandtext = "UPDATE policies SET IsSigned = 1 WHERE PolicyGUID = @PolicyGUID"
        } elseif ($Unset) {
            $Command.Commandtext = "UPDATE policies SET IsSigned = 0 WHERE PolicyGUID = @PolicyGUID"
        }
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

function Set-WDACPolicyEnforced {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Set,
        [switch]$Unset,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if ((-not $Set) -and (-not $Unset)) {
        throw "Set-WDACPolicyEnforced function called without setting `"set`" or `"unset`" flags."
    } elseif ($Set -and $Unset) {
        throw "Cannot set both `"set`" and `"unset`" flags for cmdlet Set-WDACPolicyEnforced"
    }

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        if ($Set) {
            $Command.Commandtext = "UPDATE policies SET AuditMode = 0 WHERE PolicyGUID = @PolicyGUID"
        } elseif ($Unset) {
            $Command.Commandtext = "UPDATE policies SET AuditMode = 1 WHERE PolicyGUID = @PolicyGUID"
        }
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

function Set-LastSignedUnsignedWDACPolicyVersion {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyVersion,
        [switch]$Signed,
        [switch]$Unsigned,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if ((-not $Signed) -and (-not $Unsigned)) {
        throw "Signed or Unsigned flags not set for Set-LastSignedUnsignedWDACPolicyVersion."
    }

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        if ($Signed) {
            $Command.Commandtext = "UPDATE policies SET LastSignedVersion = @LastSignedVersion WHERE PolicyGUID = @PolicyGUID"
            $Command.Parameters.AddWithValue("LastSignedVersion",$PolicyVersion) | Out-Null
        } elseif ($Unsigned) {
            $Command.Commandtext = "UPDATE policies SET LastUnsignedVersion = @LastUnsignedVersion WHERE PolicyGUID = @PolicyGUID"
            $Command.Parameters.AddWithValue("LastUnsignedVersion",$PolicyVersion) | Out-Null
        }
        
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

function Test-WDACPolicySigned {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
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
        $Command.Commandtext = "Select IsSigned from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [bool]$Reader["IsSigned"]
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

function Get-WDACPoliciesById {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyID,
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
        
        $Command.Commandtext = "Select * from policies WHERE PolicyID = @PolicyID"
        $Command.Parameters.AddWithValue("PolicyID",$PolicyID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
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

function Get-WDACPolicyByName {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
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
        $Command.Commandtext = "Select * from policies WHERE PolicyName = @PolicyName"
        $Command.Parameters.AddWithValue("PolicyName",$PolicyName) | Out-Null
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

function Get-WDACPoliciesGUIDandName {
    [cmdletbinding()]
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
        $Command.Commandtext = "SELECT PolicyGUID,PolicyName From policies;"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Get-AllWDACPoliciesAndAllInfo {
    [cmdletbinding()]
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
        $Command.Commandtext = "SELECT * From policies;"
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $Result += [PSCustomObject]@{
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

function Get-WDACPolicyAssignments {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [switch]$IncludeGroupName,
        [switch]$IncludePolicyName,
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
        if ($IncludePolicyName) {
            $Command.Commandtext = "Select GroupName,policies.PolicyGUID,PolicyName From policy_assignments INNER JOIN policies on policy_assignments.PolicyGUID = policies.PolicyGUID Where GroupName = @GroupName;"
        } else {
            $Command.Commandtext = "Select * from policy_assignments WHERE GroupName = @GroupName"
        }
        $Command.Parameters.AddWithValue("GroupName",$GroupName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                if ($IncludePolicyName) {
                    if ($IncludeGroupName) {
                        $result += [PSCustomObject]@{
                            GroupName = $GroupName
                            PolicyGUID = $Reader["PolicyGUID"]
                            PolicyName = $Reader["PolicyName"]
                        }
                    } else {
                        $result += [PSCustomObject]@{
                            PolicyGUID = $Reader["PolicyGUID"]
                            PolicyName = $Reader["PolicyName"]
                        }
                    }
                } else {
                    if ($IncludeGroupName) {
                        $result += [PSCustomObject]@{
                            GroupName = $GroupName
                            PolicyGUID = $Reader["PolicyGUID"]
                        }
                    } else {
                        $result += [PSCustomObject]@{
                            PolicyGUID = $Reader["PolicyGUID"]
                        }
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

function Get-WDACPublisher {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$LeafCertCN,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PcaCertTBSHash,
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

function Get-WDACPublisherByPublisherIndex {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
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
        $AllowedPolicyID,
        $DeferredPolicyIndex,
        $Comment,
        $BlockingPolicyID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO publishers (LeafCertCN,PcaCertTBSHash,Untrusted,TrustedDriver,TrustedUserMode,Staged,Revoked,Deferred,Blocked,AllowedPolicyID,DeferredPolicyIndex,Comment,BlockingPolicyID,PublisherIndex) values (@LeafCertCN,@PcaCertTBSHash,@Untrusted,@TrustedDriver,@TrustedUserMode,@Staged,@Revoked,@Deferred,@Blocked,@AllowedPolicyID,@DeferredPolicyIndex,@Comment,@BlockingPolicyID,(SELECT IFNULL(Max(PublisherIndex), 0) + 1 FROM publishers))"
            $Command.Parameters.AddWithValue("LeafCertCN",$LeafCertCN) | Out-Null
            $Command.Parameters.AddWithValue("PcaCertTBSHash",$PcaCertTBSHash) | Out-Null
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

function Update-WDACFilePublisherMinimumAllowedVersion {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $SpecificFileNameLevel,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$MinimumAllowedVersion,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("NewVersion","NewFileVersion","NewMin","NewMinimum","NewMinFileVersion")]
        [string]$NewMinimumAllowedVersion,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE file_publishers SET MinimumAllowedVersion = @NewMinimumAllowedVersion WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("MinimumAllowedVersion",$MinimumAllowedVersion) | Out-Null
        $Command.Parameters.AddWithValue("NewMinimumAllowedVersion",$NewMinimumAllowedVersion) | Out-Null
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

function Find-WDACFilePublisher {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$MinimumAllowedVersion,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $SpecificFileNameLevel,
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
        $Command.Commandtext = "Select * from file_publishers WHERE FileName = @FileName AND PublisherIndex = @PublisherIndex AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("MinimumAllowedVersion",$MinimumAllowedVersion) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Get-WDACFilePublishers {
#Gets Multiple File Publishers!
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
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

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
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

function Get-WDACFilePublishersDefinitive {
#This is similar Get-WDACFilePublishers but doesn't consider MaximumAllowedVersion
#FileName is also required in this function
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $FileName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $SpecificFileNameLevel,
        $MinimumAllowedVersion,
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
        if ($MinimumAllowedVersion) {
            $Command.Commandtext = "Select * from file_publishers WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
            $Command.Parameters.AddWithValue("MinimumAllowedVersion",$MinimumAllowedVersion) | Out-Null
        } else {
            $Command.Commandtext = "Select * from file_publishers WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
        }
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
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

function Add-WDACFilePublisher {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$PublisherIndex,
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

function Get-WDACFilePublisherPreferredVersioning {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt
    )

    $VersioningOptions = @'
    0 - GLOBAL SET MINIMUM - For a particular publisher index + file name + SpecificFileNameLevel combination, prompt the user for a [fixed] MinimumFileVersion that will be applied anytime the combination appears (applied to ALL policies)
        1 - GLOBAL DECREMENT MINIMUM - For a particular publisher index + file name + SpecificFileNameLevel combination, replace the MinimumFileVersion with a new one anytime a lower one appears for all appearances of the combination
        2 - GLOBAL ALWAYS SPECIFY - Anytime a new FileVersion is encountered for a publisher index + file name + SpecificFileNameLevel combination, prompt the user whether they want to change the MinimumFileVersion (applied to this combination for ALL policies)
        3 - GLOBAL INCREMENT MINIMUM - For a particular publisher index + file name + SpecificFileNameLevel combination, replace the MinimumFileVersion with a new one anytime a GREATER one appears for all appearances of the combination
        4 - GLOBAL 0.0.0.0 MINIMUM - Exactly like option 0, but 0.0.0.0 will always be set to be the MinimumFileVersion without prompting the user
        5 - GLOBAL DECREMENT MINIMUM NOT EXCEEDING MINIMUM_TOLERABLE_MINIMUM - Similar to option 1, but each time the MinimumFileVersion is replaced with a lower encountered file version, it cannot go lower than a MinimumTolerableMinimum specified by the user.
        6 - EACH POLICY SET MINIMUM - Prompt the user whether they want a [fixed] MinimumFileVersion for each time a new publisher index + file name + SpecificFileNameLevel combination is encountered for each individual policy. 
        7 - EACH POLICY DECREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a lower one anytime a lower one is encountered
        8 - EACH POLICY ALWAYS SPECIFY - Similar to option 2, but anytime a new publisher index + file name + SpecificFileNameLevel combination is encountered for EACH POLICY, the user will be prompted if they want to change the MinimumFileVersion
        9 - EACH POLICY INCREMENT MINIMUM - For each policy, specify whether that policy should replace MinimumFileVersion with a HIGHER one anytime a higher one is encountered
        10 - EACH POLICY 0.0.0.0 Minimum - Exactly like option 6, but the MinimumFileVersion will always be set to 0.0.0.0 without prompting the user
        11 - EACH POLICY DECREMENT MINIMUM NOT EXCEEDING MINIMUM_TOLERABLE_MINIMUM - Similar to option 7, but each time the MinimumFileVersion is replaced with a lower encountered file version, it cannot go lower than a MinimumTolerableMinimum specified by the user (which must be specified for each policy)
'@

    Write-Host ($Prompt + " (If unsure, select `"8`" or type `"HELP`" for information about VersioningTypes)")
    $VersioningType = Read-Host -Prompt "Selection"
    while (-not ((0..11) -contains $VersioningType)) {
        if ($VersioningType.ToLower() -eq "help" -or $VersioningType.ToLower() -eq "`"help`"") {
            Write-Host $VersioningOptions
            $VersioningType = Read-Host -Prompt "Selection"
        } else {
            Write-Host "Not a valid VersioningType value. Please provide an integer from 0 to 11 or `"HELP`""
            $VersioningType = Read-Host -Prompt "Selection"
        }
    }

    return $VersioningType
}

function New-WDACFilePublisherByCriteria {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $FileName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [ValidateSet("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")]
        $SpecificFileNameLevel="OriginalFileName",
        $VersioningType,
        [switch]$ApplyVersioningToEntirePolicy,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $PolicyID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $CurrentVersionNum,
        [switch]$IsBlocking,
        $Comment,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $ThePublisher = Get-WDACPublisherByPublisherIndex -PublisherIndex $PublisherIndex -Connection $Connection -ErrorAction Stop
        $TempFilePublisherOptions = Get-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop
        $NewVersionNumber = $null

        if ($IsBlocking) {
            $NewVersionNumber = Get-FileVersionPrompt -Prompt "What MinimumVersionNumber would you like to set for this file publisher block rule?" -FileVersionInfo "FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
            Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -BlockingPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
            return $NewVersionNumber
        }
                
        if (-not $VersioningType) {
            $PolicyVersioningOptions = Get-PolicyVersioningOptions -PolicyGUID $PolicyID -Connection $Connection -ErrorAction Stop
            if ($PolicyVersioningOptions) {
                $VersioningType = $PolicyVersioningOptions.VersioningType
            } elseif ($TempFilePublisherOptions) {
                $VersioningType = $TempFilePublisherOptions.VersioningType
            } else {
                $VersioningType = Get-WDACFilePublisherPreferredVersioning -Prompt "What versioning type would you like to use for this file publisher?"
            }
        } elseif ($ApplyVersioningToEntirePolicy) {
            $PolicyVersioningOptions = Get-PolicyVersioningOptions -PolicyGUID $PolicyID -Connection $Connection -ErrorAction Stop
            if (-not $PolicyVersioningOptions) {
                Add-PolicyVersioningOptions -PolicyGUID $PolicyID -VersioningType $VersioningType -Connection $Connection -ErrorAction Stop | Out-Null
            }
        }

        if ($VersioningType -gt 5) {
            $TempPolicyFilePublisherOptions = Get-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop
        }

        switch ($VersioningType) {
            0 {
                if ($TempFilePublisherOptions) {
                    $NewVersionNumber = $TempFilePublisherOptions.MinimumAllowedVersionPivot
                    Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                } else {
                    $NewVersionNumber = Get-FileVersionPrompt -Prompt "What fixed Global MinimumVersionNumber would you like to set for this file publisher? " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                    Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                    Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 0 -Connection $Connection -ErrorAction Stop | Out-Null
                    Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                }
                
                return $NewVersionNumber
            }
            
            1 {
                if ($TempFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($TempFilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return $CurrentVersionNum
                    } else {
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion ($TempFilePublisherOptions.MinimumAllowedVersionPivot) -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return ($TempFilePublisherOptions.MinimumAllowedVersionPivot)
                    }
                }
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 1 -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                return $CurrentVersionNum
            }

            2 {
                if ($TempFilePublisherOptions) {
                    if ($TempFilePublisherOptions.MinimumAllowedVersionPivot -ne $CurrentVersionNum) {
                        $NewVersionNumber = Get-FileVersionOldAndNewPrompt -Prompt "New minimum version number encountered for this filename + publisher index combination. " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -PreviousVersionNum ($TempFilePublisherOptions.MinimumAllowedVersionPivot) -CurrentVersionNum $CurrentVersionNum
                        if ($NewVersionNumber -ne $TempFilePublisherOptions.MinimumAllowedVersionPivot) {
                            Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                        }
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return $NewVersionNumber
                    }
                }
                $NewVersionNumber = Get-FileVersionPrompt -Prompt "What current MinimumVersionNumber would you like to set for this file publisher? " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 2 -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                return $NewVersionNumber
            }

            3 {
                if ($TempFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($TempFilePublisherOptions.MinimumAllowedVersionPivot)) -eq 1) {
                        Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return $CurrentVersionNum
                    } else {
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion ($TempFilePublisherOptions.MinimumAllowedVersionPivot) -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return ($TempFilePublisherOptions.MinimumAllowedVersionPivot)
                    }
                }
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 3 -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                return $CurrentVersionNum
            }

            4 {
                $NewVersionNumber = "0.0.0.0"
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                if (-not $TempFilePublisherOptions) {
                    Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 4 -Connection $Connection -ErrorAction Stop | Out-Null
                    Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                }
                return $NewVersionNumber
            }

            5 {
                if ($TempFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($TempFilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        $TempPivot = $CurrentversionNum
                    } else {
                        $TempPivot = $TempFilePublisherOptions.MinimumAllowedVersionPivot
                    }

                    if ((Compare-Versions -Version1 $TempPivot -Version2 ($TempFilePublisherOptions.MinimumTolerableMinimum)) -eq -1) {
                        $NewVersionNumber = $TempFilePublisherOptions.MinimumTolerableMinimum
                    } else {
                        $NewVersionNumber = $TempPivot
                    }

                    Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                    return $NewVersionNumber
                }
                $NewVersionNumber = Get-FileVersionPrompt -Prompt "What is the minimum tolerable minimum for this file publisher? " -FileVersionInfo "FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                while ( (Compare-Versions -Version1 ($NewVersionNumber) -Version2 ($CurrentVersionNum)) -eq 1) {
                    $NewVersionNumber = Get-FileVersionPrompt -Prompt "Minimum tolerable minimum cannot be greater than the current FileVersion. Give a valid Minimum Tolerable Minimum." -FileVersionInfo "FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                }
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 5 -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumTolerableMinimum -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                return $CurrentVersionNum
            }

            6 {
                if ($TempPolicyFilePublisherOptions) {
                    $NewVersionNumber = $TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot
                    Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                } else {
                    $NewVersionNumber = Get-FileVersionPrompt -Prompt "Different for each policy: What fixed MinimumVersionNumber would you like to set for this file publisher? " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                    Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                    Add-FilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 6 -Connection $Connection -ErrorAction Stop | Out-Null
                    Add-PolicyFilePublisherOptions  -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                    Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                }
                
                return $NewVersionNumber
            }

            7 {
                if ($TempPolicyFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return $CurrentVersionNum
                    } else {
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot) -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot)
                    }
                }
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 7 -Connection $Connection -ErrorAction Stop | Out-Null
                Add-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                return $CurrentVersionNum
            }

            8 {
                if ($TempPolicyFilePublisherOptions) {
                    if ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot -ne $CurrentVersionNum) {
                        $NewVersionNumber = Get-FileVersionOldAndNewPrompt -Prompt "New minimum version number encountered for this filename + publisher index combination. " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -PreviousVersionNum ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot) -CurrentVersionNum $CurrentVersionNum
                        if ($NewVersionNumber -ne $TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot) {
                            Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                        }
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return $NewVersionNumber
                    }
                }
                $NewVersionNumber = Get-FileVersionPrompt -Prompt "Different for each policy: What current MinimumVersionNumber would you like to set for this file publisher? " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 8 -Connection $Connection -ErrorAction Stop | Out-Null
                Add-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                return $NewVersionNumber
            }

            9 {
                if ($TempPolicyFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot)) -eq 1) {
                        Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return $CurrentVersionNum
                    } else {
                        Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot) -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                        return ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot)
                    }
                }
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 9 -Connection $Connection -ErrorAction Stop | Out-Null
                Add-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                return $CurrentVersionNum
            }

            10 {
                $NewVersionNumber = "0.0.0.0"
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                if (-not $TempFilePublisherOptions) {
                    Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 10 -Connection $Connection -ErrorAction Stop | Out-Null
                }
                if (-not $TempPolicyFilePublisherOptions) {
                    Add-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                    Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                }
                
                return $NewVersionNumber
            }

            11 {
                if ($TempPolicyFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        $TempPivot = $CurrentversionNum
                    } else {
                        $TempPivot = $TempPolicyFilePublisherOptions.MinimumAllowedVersionPivot
                    }

                    if ((Compare-Versions -Version1 $TempPivot -Version2 ($TempPolicyFilePublisherOptions.MinimumTolerableMinimum)) -eq -1) {
                        $NewVersionNumber = $TempPolicyFilePublisherOptions.MinimumTolerableMinimum
                    } else {
                        $NewVersionNumber = $TempPivot
                    }

                    Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $NewVersionNumber -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                    return $NewVersionNumber
                }
                $NewVersionNumber = Get-FileVersionPrompt -Prompt "Different for each policy: What is the minimum tolerable minimum for this file publisher? " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                while ( (Compare-Versions -Version1 ($NewVersionNumber) -Version2 ($CurrentVersionNum)) -eq 1) {
                    $NewVersionNumber = Get-FileVersionPrompt -Prompt "Minimum tolerable minimum cannot be greater than the current FileVersion. Give a valid Minimum Tolerable Minimum." -FileVersionInfo "FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -CurrentVersionNum $CurrentVersionNum
                }
                Add-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -AllowedPolicyID $PolicyID -Comment $Comment -MinimumAllowedVersion $CurrentVersionNum -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Add-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -VersioningType 11 -Connection $Connection -ErrorAction Stop | Out-Null
                Add-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumTolerableMinimum -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                return $CurrentVersionNum
            }
        }

    } catch {
        throw $_
    }
}

function Update-WDACFilePublisherByCriteriaHelper {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $FileName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SpecificFileNameLevel,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $MinimumVersionNumber,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $CurrentVersionNum,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $VersioningType = $null
    $PolicyID = $PolicyGUID

    try {
        $PolicyFilePublisherOptions = Get-PolicyFilePublisherOptions -PolicyGUID $PolicyGUID -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -PublisherIndex $PublisherIndex -Connection $Connection -ErrorAction Stop
        $FilePublisherOptions = Get-FilePublisherOptions -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -PublisherIndex $PublisherIndex -Connection $Connection -ErrorAction Stop
        $PolicyVersioningOptions = Get-PolicyVersioningOptions -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        ###### CHECK FOR POLICY FILE PUBLISHER OPTIONS ##################
        if ( ($PolicyFilePublisherOptions -and $FilePublisherOptions) -or $FilePublisherOptions) {
        #The versioning type is stored in the file_publisher_options table even if a policy_file_publisher_options entry exists
            $VersioningType = $FilePublisherOptions.VersioningType
        }
        #################################################################

        ###### USE THE POLICY'S VersioningType or the if NO OTHER ENTRIES ######
        elseif ($PolicyVersioningOptions) {
            $VersioningType = $PolicyVersioningOptions.VersioningType
        }
        ################################################################################################
        else {
            return;
        }

        switch ($VersioningType) {
            0 {
                #Global Set Minimum will not prompt the user for a new Minimum File Version
                return;
            }
            
            1 {
                if ($FilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($FilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop)) {
                            Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        } else {
                            Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $CurrentVersionNum -- as there is already an entry with that MinimumAllowedVersion in the database."
                        }
                    } 
                }
                return;
            }

            2 {
                if ($FilePublisherOptions) {
                    if ($FilePublisherOptions.MinimumAllowedVersionPivot -ne $CurrentVersionNum) {
                        $NewVersionNumber = Get-FileVersionOldAndNewPrompt -Prompt "New minimum version number encountered for this filename + publisher index combination. " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -PreviousVersionNum ($FilePublisherOptions.MinimumAllowedVersionPivot) -CurrentVersionNum $CurrentVersionNum
                        
                        if ($NewVersionNumber -ne $FilePublisherOptions.MinimumAllowedVersionPivot) {
                            Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                        }

                        if ($NewVersionNumber -ne $FilePublisherOptions.MinimumAllowedVersionPivot -and ($NewVersionNumber -ne $MinimumVersionNumber)) {
                            if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop)) {
                                Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                            } else {
                                Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $NewVersionNumber -- as there is already an entry with that MinimumAllowedVersion in the database."
                            }
                        }
                    }
                }
                return;
            }

            3 {
                if ($FilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($FilePublisherOptions.MinimumAllowedVersionPivot)) -eq 1) {
                        Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop)) {
                            Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        } else {
                            Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $CurrentVersionNum -- as there is already an entry with that MinimumAllowedVersion in the database."
                        }
                    } 
                }
            }

            4 {
                #Assume that the minimum file version is already 0.0.0.0 and return
                return;
            }

            5 {
                if ($FilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($FilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-FilePublisherOptions -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        $TempPivot = $CurrentversionNum
                    } else {
                        $TempPivot = $FilePublisherOptions.MinimumAllowedVersionPivot
                    }

                    if ((Compare-Versions -Version1 $TempPivot -Version2 ($FilePublisherOptions.MinimumTolerableMinimum)) -eq -1) {
                        $NewVersionNumber = $FilePublisherOptions.MinimumTolerableMinimum
                    } else {
                        $NewVersionNumber = $TempPivot
                    }

                    if ($NewVersionNumber -ne $MinimumVersionNumber) {
                        if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop)) {
                            Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                        } else {
                            Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $CurrentVersionNum -- as there is already an entry with that MinimumAllowedVersion in the database."
                        }
                    }
                }
                return;
            }

            6 {
                #EACH POLICY SET MINIMUM will not prompt the user for a new Minimum File Version
                return;
            }

            7 {
                if ($PolicyFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($PolicyFilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel  -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop)) {
                            Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        } else {
                            Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $CurrentVersionNum -- as there is already an entry with that MinimumAllowedVersion in the database."
                        }
                    } 
                }
                return;
            }

            8 {
                if ($PolicyFilePublisherOptions) {
                    if ($PolicyFilePublisherOptions.MinimumAllowedVersionPivot -ne $CurrentVersionNum) {
                        $NewVersionNumber = Get-FileVersionOldAndNewPrompt -Prompt "New minimum version number encountered for this filename + publisher index combination. " -FileVersionInfo " FileVersion for this app is $CurrentVersionNum .`n FilePublisher info: FileName $FileName and Publisher Common Name: $($ThePublisher.LeafCertCN) and PcaCertTBSHash: $($ThePublisher.PcaCertTBSHash)" -PreviousVersionNum ($PolicyFilePublisherOptions.MinimumAllowedVersionPivot) -CurrentVersionNum $CurrentVersionNum
                        
                        if ($NewVersionNumber -ne $PolicyFilePublisherOptions.MinimumAllowedVersionPivot) {
                            Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                        }
                        if ($NewVersionNumber -ne $PolicyFilePublisherOptions.MinimumAllowedVersionPivot -and ($NewVersionNumber -ne $MinimumVersionNumber)) {
                            if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop)) {
                                Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                            } else {
                                Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $NewVersionNumber -- as there is already an entry with that MinimumAllowedVersion in the database."
                            }
                        }
                    }
                }
                return;
            }

            9 {
                if ($FilePublisherOptions -and ( $PolicyFilePublisherOptions)) {
                    if ($PolicyFilePublisherOptions) {
                        if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($PolicyFilePublisherOptions.MinimumAllowedVersionPivot)) -eq 1) {
                            Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                            if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop)) {
                                Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                            } else {
                                Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $CurrentVersionNum -- as there is already an entry with that MinimumAllowedVersion in the database."
                            }
                        } 
                    }
                    return;
                }
            }

            10 {
                #Assume that the minimum file version is already 0.0.0.0 and return
                return;
            }

            11 {
                if ($PolicyFilePublisherOptions) {
                    if ( (Compare-Versions -Version1 $CurrentVersionNum -Version2 ($PolicyFilePublisherOptions.MinimumAllowedVersionPivot)) -eq -1) {
                        Edit-PolicyFilePublisherOptions -PolicyGUID $PolicyID -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -NewValue $CurrentVersionNum -Connection $Connection -ErrorAction Stop | Out-Null
                        $TempPivot = $CurrentversionNum
                    } else {
                        $TempPivot = $PolicyFilePublisherOptions.MinimumAllowedVersionPivot
                    }

                    if ((Compare-Versions -Version1 $TempPivot -Version2 ($PolicyFilePublisherOptions.MinimumTolerableMinimum)) -eq -1) {
                        $NewVersionNumber = $PolicyFilePublisherOptions.MinimumTolerableMinimum
                    } else {
                        $NewVersionNumber = $TempPivot
                    }

                    if ($NewVersionNumber -ne $MinimumVersionNumber) {
                        if (-not (Find-WDACFilePublisher -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop)) {
                            Update-WDACFilePublisherMinimumAllowedVersion -PublisherIndex $PublisherIndex -FileName $FileName -SpecificFileNameLevel $SpecificFileNameLevel -MinimumAllowedVersion $MinimumVersionNumber -NewMinimumAllowedVersion $NewVersionNumber -Connection $Connection -ErrorAction Stop | Out-Null
                        } else {
                            Write-Warning "Could not update FilePublisher rule with publisher index $PublisherIndex and FileName $FileName to version $CurrentVersionNum -- as there is already an entry with that MinimumAllowedVersion in the database."
                        }
                    }
                }
                return;
            }
        }

    } catch {
        throw $_
    }
}

function Update-WDACFilePublisherByCriteria {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $SpecificFileNameLevels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")

    try {
    ###### FIRST CHECK FOR FILE PUBLISHER ENTRIES WITH TRUST AND POLICY ID SET #################
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $WDACApp = Get-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        if ($WDACApp.FileVersion) {
            $CertInfo = (Expand-WDACAppV2 -SHA256FlatHash $SHA256FlatHash -Levels "FilePublisher" -Connection $Connection -ErrorAction Stop | Select-Object CertsAndPublishers).CertsAndPublishers

            foreach ($Signer in $CertInfo) {
                foreach ($FileNameLevel in $SpecificFileNameLevels) {
                    if ($Signer.FilePublishers.$($FileNameLevel)) {
                        $TempFilePublishers = $Signer.FilePublishers.$($FileNameLevel)
                        foreach ($TempFilePublisher in $TempFilePublishers) {
                            if ( ($null -ne $TempFilePublisher.AllowedPolicyID) -and ("" -ne $TempFilePublisher.AllowedPolicyID)) {
                                Update-WDACFilePublisherByCriteriaHelper -FileName $TempFilePublisher.FileName -PublisherIndex $TempFilePublisher.PublisherIndex -SpecificFileNameLevel $FileNameLevel -MinimumVersionNumber $TempFilePublisher.MinimumAllowedVersion -PolicyGUID $TempFilePublisher.AllowedPolicyID -CurrentVersionNum $WDACApp.FileVersion -Connection $Connection -ErrorAction Stop
                            } elseif ($TempFilePublisher.BlockingPolicyID) {
                                #TODO
                            }
                        }
                    }
                }
            }
        }
        
    ###########################################################################################
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

function Add-WDACDevice {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$AllowedGroup,
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

function Add-WDACPolicyAdHocAssignment {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()

        $Command.Commandtext = "INSERT INTO ad_hoc_policy_assignments (PolicyGUID,DeviceName) values (@PolicyGUID,@DeviceName)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
            
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

function Find-WDACPolicyAdHocAssignment {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
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
        $Command.Commandtext = "Select * from ad_hoc_policy_assignments WHERE PolicyGUID = @PolicyGUID AND DeviceName = @DeviceName"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
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

function Add-WDACPolicyAssignment {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
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
                    if (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -ErrorAction Stop) {
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
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SpecificFileNameLevel,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $SpecificFileNameLevels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")
    if (-not ($SpecificFileNameLevels -contains $SpecificFileNameLevel)) {
        throw "$SpecificFileNameLevel is not a valid SpecificFileName level."
    }

    $result = $null
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select * from file_names WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
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

function Expand-WDACApp {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [switch]$AddPublisher,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $Result = @()
    try {
        $Signers = Get-WDACAppSignersByFlatHash -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        if (-not $Signers) {
            return $null
        }

        foreach ($Signer in $Signers) {
            $LeafCertTBSHash = $Signer.CertificateTBSHash
            $LeafCert = Get-WDACCertificate -TBSHash $LeafCertTBSHash -Connection $Connection -ErrorAction Stop

            if ($LeafCert.ParentCertTBSHash) {
                $PcaCert = Get-WDACCertificate -TBSHash $LeafCert.ParentCertTBSHash -Connection $Connection -ErrorAction Stop
                $Publisher = Get-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -Connection $Connection -ErrorAction Stop
                if (-not $Publisher -and $AddPublisher) {
                #If publisher isn't in the database, then add it--but only if those are specified levels the user wants
                    if (-not (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -Connection $Connection -ErrorAction Stop)) {
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

function Expand-WDACAppV2 {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [switch]$AddPublisher,
        $Levels,
        [Alias("Certs")]
        [switch]$GetCerts,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $Levels) {
        $Levels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    } else {
        foreach ($LevelProvided in $Levels) {
            if (-not (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher") -contains $LevelProvided)) {
                throw "Please provide one or more of the following levels: Hash,FilePath,FileName,LeafCertificate,PcaCertificate,Publisher,FilePublisher"
            }
        }
    }
    $SpecificFileNameLevels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")
    
    if (-not ($Levels -contains "LeafCertificate") -and $GetCerts) {
        $Levels += "LeafCertificate"
    }
    if (-not ($Levels -contains "PcaCertificate") -and $GetCerts) {
        $Levels += "PcaCertificate"
    }

    $App = Get-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
    if (-not $App) {
        return $null
    }

    $Result = @{}
    $CertsAndPublishers = @()
    try {
        $Signers = Get-WDACAppSignersByFlatHash -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        if (-not $Signers) {
            return $null
        }

        foreach ($Signer in $Signers) {
            $LeafCertTBSHash = $Signer.CertificateTBSHash
            $LeafCert = Get-WDACCertificate -TBSHash $LeafCertTBSHash -Connection $Connection -ErrorAction Stop

            if ($LeafCert.ParentCertTBSHash) {
                $PcaCert = Get-WDACCertificate -TBSHash $LeafCert.ParentCertTBSHash -Connection $Connection -ErrorAction Stop
                $Publisher = Get-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -Connection $Connection -ErrorAction Stop
                if (-not $Publisher -and $AddPublisher) {
                #If publisher isn't in the database, then add it--but only if those are specified levels the user wants
                    if (-not (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -Connection $Connection -ErrorAction Stop)) {
                        throw "Trouble adding a publisher to the database."
                    } else {
                        $Publisher = Get-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -Connection $Connection -ErrorAction Stop
                    }
                }
            }

            $TempDict = @{}
            #@{SignatureIndex = $Signer.SignatureIndex; SignerInfo = ( $Signer | Select-Object SignatureType,PageHash,Flags,PolicyBits,ValidatedSigningLevel,VerificationError); LeafCert = $LeafCert; PcaCert = $PcaCert; Publisher = $Publisher; }
            $TempDict.Add("SignatureIndex",$Signer.SignatureIndex)
            $TempDict.Add("SignerInfo",( $Signer | Select-Object SignatureType,PageHash,Flags,PolicyBits,ValidatedSigningLevel,VerificationError))
            switch ($Levels) {
                "LeafCertificate" {
                    $TempDict.Add("LeafCert",$LeafCert)
                }
                "PcaCertificate" {
                    $TempDict.Add("PcaCertificate",$PcaCert)
                }
                "Publisher" {
                    $TempDict.Add("Publisher",$Publisher)
                } 
                "FilePublisher" {
                    $FilePublishersList = @{}
                    if ($Publisher) {
                        foreach ($FileNameLevel in $SpecificFileNameLevels) {
                            if ($App.$($FileNameLevel)) {
                                $FilePublishers = Get-WDACFilePublishers -PublisherIndex $Publisher.PublisherIndex -FileName $App.$($FileNameLevel) -SpecificFileNameLevel $FileNameLevel -Connection $Connection -ErrorAction Stop
                                if ($FilePublishers) {
                                    $FilePublishersList.Add($FileNameLevel,$FilePublishers)
                                }
                            }
                        }
                        if ($FilePublishersList.Count -ge 1) {
                            $TempDict.Add("FilePublishers",$FilePublishersList)
                        }
                    }
                }
            }

            $CertsAndPublishers += $TempDict
        }

        if ($Levels -contains "FileName") {
            foreach ($FileNameLevel in $SpecificFileNameLevels) {
                if ($App.$($FileNameLevel)) {
                    $FileName = Get-WDACFileName -FileName $App.$($FileNameLevel) -SpecificFileNameLevel $FileNameLevel -Connection $Connection -ErrorAction Stop
                    if ($FileName) {
                        $Result.Add("FileName",$FileName)
                        break
                    }
                }
            }
        }
        if ($Levels -contains "LeafCertificate" -or $Levels -contains "PcaCertificate" -or $Levels -contains "Publisher" -or $Levels -contains "FilePublisher") {
            $CertsAndPublishers = $CertsAndPublishers | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }
            $Result.Add("CertsAndPublishers",$CertsAndPublishers)
        }
        if ($Levels -contains "Hash") {
            $Result.Add("Hash",$App)
        }

        $ResultObj = $Result | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }
        return $ResultObj
    } catch {
        throw $_
    }
}

function Add-NewPublishersFromAppSigners {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

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
                
                if (-not ($Publisher)) {
                    if ($Connection) {
                        if (-not (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -Connection $Connection -ErrorAction Stop)) {
                            throw "Trouble adding a publisher to the database."
                        } 
                    }
                    elseif (-not (Add-WDACPublisher -LeafCertCN $LeafCert.CommonName -PcaCertTBSHash $PcaCert.TBSHash -ErrorAction Stop)) {
                        throw "Trouble adding a publisher to the database."
                    } 
                }
            }
        }
    } catch {
        throw $_
    }
}

function Set-WDACSkipped {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection,
        [switch]$UndoSkip
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()

        if (Find-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection) {
            if ($UndoSkip) {
                $Command.Commandtext = "UPDATE apps SET Skipped = 0 WHERE SHA256FlatHash = @SHA256FlatHash"
            } else {
                $Command.Commandtext = "UPDATE apps SET Skipped = 1 WHERE SHA256FlatHash = @SHA256FlatHash"
            }
        }
        elseif (Find-MSIorScript -SHA256FlatHash $SHA256FlatHash -Connection $Connection) {
            if ($UndoSkip) {
                $Command.Commandtext = "UPDATE msi_or_script SET Skipped = 0 WHERE SHA256FlatHash = @SHA256FlatHash"
            } else {
                $Command.Commandtext = "UPDATE msi_or_script SET Skipped = 1 WHERE SHA256FlatHash = @SHA256FlatHash"
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

function Set-WDACUntrusted {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$SHA256FlatHash,
        [System.Data.SQLite.SQLiteConnection]$Connection,
        [switch]$UndoUntrust
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()

        if (Find-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection) {
            if ($UndoUntrust) {
                $Command.Commandtext = "UPDATE apps SET Untrusted = 0 WHERE SHA256FlatHash = @SHA256FlatHash"
            } else {
                $Command.Commandtext = "UPDATE apps SET Untrusted = 1 WHERE SHA256FlatHash = @SHA256FlatHash"
            }
        }
        elseif (Find-MSIorScript -SHA256FlatHash $SHA256FlatHash -Connection $Connection) {
            if ($UndoUntrust) {
                $Command.Commandtext = "UPDATE msi_or_script SET Untrusted = 0 WHERE SHA256FlatHash = @SHA256FlatHash"
            } else {
                $Command.Commandtext = "UPDATE msi_or_script SET Untrusted = 1 WHERE SHA256FlatHash = @SHA256FlatHash"
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

function Clear-AllWDACSkipped {
    [CmdletBinding()]
    Param (
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $AllAppHashes = Get-WDACAppsAllHashes -Connection $Connection -ErrorAction Stop
        $AllMSIorScriptHashes = Get-MSIorScriptAllHashes -Connection $Connection -ErrorAction Stop

        foreach ($Hash in $AllAppHashes) {
            if (Get-WDACAppSkippedStatus -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -ErrorAction Stop) {
                if (-not (Set-WDACSkipped -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -UndoSkip -ErrorAction Stop)) {
                    throw "Coud not clear skipped status for $Hash "
                }
            }
        }
        foreach ($Hash in $AllMSIorScriptHashes) {
            if (Get-MSIorScriptSkippedStatus -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -ErrorAction Stop) {
                if (-not (Set-WDACSkipped -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -UndoSkip -ErrorAction Stop)) {
                    throw "Could not clear skipped status for $Hash "
                }
            }
        }

    } catch {
        throw $_
    }
}

function Clear-AllWDACUntrusted {
    [CmdletBinding()]
    Param (
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $AllAppHashes = Get-WDACAppsAllHashes -Connection $Connection -ErrorAction Stop
        $AllMSIorScriptHashes = Get-MSIorScriptAllHashes -Connection $Connection -ErrorAction Stop

        foreach ($Hash in $AllAppHashes) {
            if (Get-WDACAppUntrustedStatus -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -ErrorAction Stop) {
                if (-not (Set-WDACUntrusted -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -UndoUntrust -ErrorAction Stop)) {
                    throw "Coud not clear skipped status for $Hash "
                }
            }
        }
        foreach ($Hash in $AllMSIorScriptHashes) {
            if (Get-MSIorScriptUntrustedStatus -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -ErrorAction Stop) {
                if (-not (Set-WDACUntrusted -SHA256FlatHash $Hash.Sha256FlatHash -Connection $Connection -UndoUntrust -ErrorAction Stop)) {
                    throw "Could not clear skipped status for $Hash "
                }
            }
        }

    } catch {
        throw $_
    }
}

function Get-AppTrusted {
#Determines if an app (WDAC event) would be able to run based on the "TrustedDriver" or "TrustedUserMode" attributes of various rule levels
    [CmdletBinding(DefaultParameterSetName = 'AppEntryPresent')]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true,ParameterSetName = 'AppEntryPresent')]
        [Alias("Hash","FlatHash")]
        [string]$SHA256FlatHash,
        [Alias("Levels")]
        $AllPossibleLevels,
        [switch]$Driver,
        [switch]$UserMode,
        [Parameter(Mandatory=$true,ParameterSetName = 'NoAppEntryPresent')]
        $WDACEvent,
        [Parameter(ParameterSetName = 'NoAppEntryPresent')]
        $CertInfoNoAppPresent,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $AllPossibleLevels) {
        $AllPossibleLevels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    } else {
        foreach ($LevelProvided in $AllPossibleLevels) {
            if (-not (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher") -contains $LevelProvided)) {
                throw "Please provide one or more of the following levels: Hash,FilePath,FileName,LeafCertificate,PcaCertificate,Publisher,FilePublisher"
            }
        }
    }
    $SpecificFileNameLevels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")

    try {
        if ($WDACEvent) {
            $AppInstance = $WDACEvent
            if ($CertInfoNoAppPresent) {
                $CertInfo = $CertInfoNoAppPresent
            }
        } else {
            $AppInstance = Get-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
            if (-not $AppInstance) {
                throw "No instance of this app $SHA256FlatHash in the database."
            }
        }

        #TODO -> MSI_OR_SCRIPT APP INSTANCE
        if (-not $CertInfo -and -not $WDACEvent) {
            $CertInfo = Expand-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        }

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
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.OriginalFileName -SpecificFileNameLevel "OriginalFileName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "InternalName" {
                            if ($AppInstance.InternalName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.InternalName -SpecificFileNameLevel "InternalName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "FileDescription" {
                            if ($AppInstance.FileDescription) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.FileDescription -SpecificFileNameLevel "FileDescription" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "ProductName" {
                            if ($AppInstance.ProductName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.ProductName -SpecificFileNameLevel "ProductName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if (Get-TrustedInstance -Instance $TempFileName -Driver:$Driver -UserMode:$UserMode -ErrorAction Stop) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "PackageFamilyName" {
                            if ($AppInstance.PackageFamilyName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.PackageFamilyName -SpecificFileNameLevel "PackageFamilyName" -Connection $Connection -ErrorAction Stop
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
                            $TempPublisher = Get-WDACPublisher -LeafCertCN $LeafCertificate.CommonName -PcaCertTBSHash $LeafCertificate.ParentCertTBSHash -Connection $Connection -ErrorAction Stop
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
                            $TempPublisher = Get-WDACPublisher -LeafCertCN $LeafCertificate.CommonName -PcaCertTBSHash $LeafCertificate.ParentCertTBSHash -Connection $Connection -ErrorAction Stop
                            if ($TempPublisher.PublisherIndex) {
                                switch ($SpecificFileNameLevels) {
                                    "OriginalFileName" {
                                        if ($AppInstance.OriginalFileName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.OriginalFileName -SpecificFileNameLevel "OriginalFileName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "InternalName" {
                                        if ($AppInstance.InternalName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.InternalName -SpecificFileNameLevel "InternalName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "FileDescription" {
                                        if ($AppInstance.FileDescription) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.FileDescription -SpecificFileNameLevel "FileDescription" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "ProductName" {
                                        if ($AppInstance.ProductName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.ProductName -SpecificFileNameLevel "ProductName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-TrustedInstanceFilePublishers -FilePublishers $TempFilePublishers -Driver:$Driver -UserMode:$UserMode -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "PackageFamilyName" {
                                        if ($AppInstance.PackageFamilyName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.PackageFamilyName -SpecificFileNameLevel "PackageFamilyName" -Connection $Connection -ErrorAction Stop
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

function Get-AppTrustedNoAppEntry {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $WDACEvent,
        $AllPossibleLevels,
        [switch]$Driver,
        [switch]$UserMode,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $AllPossibleLevels) {
        $AllPossibleLevels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    } else {
        foreach ($LevelProvided in $AllPossibleLevels) {
            if (-not (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher") -contains $LevelProvided)) {
                throw "Please provide one or more of the following levels: Hash,FilePath,FileName,LeafCertificate,PcaCertificate,Publisher,FilePublisher"
            }
        }
    }

    $AllPossibleLevels = $AllPossibleLevels | Where-Object {$_ -ne "Hash"}
    #Since Hash rules are handled by app event entries, this would be redundant, so let's just remove it

    try {

        if (-not $Driver -and -not $UserMode) {
            if ($WDACEvent.SigningScenario -eq "UserMode") {
                $UserMode = $true
            } elseif ($WDACEvent.SigningScenario -eq "Driver") {
                $Driver = $true
            } else {
                $UserMode = $true
                $Driver = $false
            }
        }


        $CertInfo = [PSCustomObject]@{
            LeafCert = @();
            PcaCert = @()
        }
    
        foreach ($Signer in $WDACEvent.SignerInfo) {

            if (($Signer.PublisherTBSHash -and -not $Signer.IssuerTBSHash) -or (-not $Signer.PublisherTBSHash -and ($Signer.IssuerTBSHash))) {
            #If there's not a matching publisher and issuer pair, then continue the loop
                continue;
            }

            if ($Signer.PublisherTBSHash) {
                $TempPublisherCert = Get-WDACCertificate -TBSHash $Signer.PublisherTBSHash -Connection $Connection -ErrorAction Stop
                if ($TempPublisherCert) {
                    $CertInfo.LeafCert += $TempPublisherCert
                }
                if ($Signer.IssuerTBSHash) {
                    $TempIssuerCert = Get-WDACCertificate -TBSHash $Signer.IssuerTBSHash -Connection $Connection -ErrorAction Stop
                    if ($TempIssuerCert) {
                        $CertInfo.PcaCert += $TempIssuerCert
                    }
                }
            }
        }

        return (Get-AppTrusted -AllPossibleLevels $AllPossibleLevels -Driver:$Driver -UserMode:$UserMode -WDACEvent $WDACEvent -CertInfoNoAppPresent $CertInfo -Connection $Connection -ErrorAction Stop)
    } catch {
        throw $_
    }
}

function Get-AppTrustedAllLevels {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Hash","FlatHash")]
        [string]$SHA256FlatHash,
        [Alias("Levels")]
        $AllPossibleLevels,
        [switch]$Driver,
        [switch]$UserMode,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $AllPossibleLevels) {
        $AllPossibleLevels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    } else {
        foreach ($LevelProvided in $AllPossibleLevels) {
            if (-not (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher") -contains $LevelProvided)) {
                throw "Please provide one or more of the following levels: Hash,FilePath,FileName,LeafCertificate,PcaCertificate,Publisher,FilePublisher"
            }
        }
    }

    $Result = [PSCustomObject]@{}
    $ResultHashTable = @{}

    foreach ($Level in $AllPossibleLevels) {
        $ResultHashTable.Add($Level,$false)
        if (Get-AppTrusted -SHA256FlatHash $SHA256FlatHash -AllPossibleLevels $Level -Driver:$Driver -UserMode:$UserMode -Connection $Connection -ErrorAction Stop) {
            $ResultHashTable[$Level] = $true
        }
    }
    
    $Result | Add-Member -NotePropertyMembers $ResultHashTable -PassThru | Out-Null
    return (Format-SQLResult $Result)
}

function Update-WDACTrust {
#This only sets non-enabled values to enabled
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrimaryKey1,
        $PrimaryKey2,
        $PrimaryKey3,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Level,
        [bool]$UserMode,
        [bool]$Driver,
        [bool]$Block,
        [bool]$Untrusted,
        [bool]$MSIorScripts,
        $SpecificFileNameLevel,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (($Level -eq "FilePublisher") -and (-not $SpecificFileNameLevel)) {
            throw "Error in Function `"Update-WDACTrust`". SpecificFileNameLevel must be provided if FilePublisher level is specified."
        }

        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        switch ($Level) {
    
            "Hash" {
                if ($MSIorScripts) {
                    #TODO
                } else {
                    if ($UserMode) {
                        $Command = $Connection.CreateCommand()
                        $Command.Commandtext = "UPDATE apps SET TrustedUserMode = 1 WHERE Sha256FlatHash = @Sha256FlatHash"
                        $Command.Parameters.AddWithValue("Sha256FlatHash",$PrimaryKey1) | Out-Null
                        $Command.ExecuteNonQuery()
                    }
                    if ($Driver) {
                        $Command = $Connection.CreateCommand()
                        $Command.Commandtext = "UPDATE apps SET TrustedDriver = 1 WHERE Sha256FlatHash = @Sha256FlatHash"
                        $Command.Parameters.AddWithValue("Sha256FlatHash",$PrimaryKey1) | Out-Null
                        $Command.ExecuteNonQuery()
                    }
                    if ($Block) {
                        $Command = $Connection.CreateCommand()
                        $Command.Commandtext = "UPDATE apps SET Blocked = 1 WHERE Sha256FlatHash = @Sha256FlatHash"
                        $Command.Parameters.AddWithValue("Sha256FlatHash",$PrimaryKey1) | Out-Null
                        $Command.ExecuteNonQuery()
                    } 
                    if ($Untrusted) {
                        $Command = $Connection.CreateCommand()
                        $Command.Commandtext = "UPDATE apps SET Untrusted = 1 WHERE Sha256FlatHash = @Sha256FlatHash"
                        $Command.Parameters.AddWithValue("Sha256FlatHash",$PrimaryKey1) | Out-Null
                        $Command.ExecuteNonQuery()
                    }
                }
            }
    
            "Publisher" {
                if ($UserMode) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE publishers SET TrustedUserMode = 1 WHERE PublisherIndex = @PublisherIndex"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Driver) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE publishers SET TrustedDriver = 1 WHERE PublisherIndex = @PublisherIndex"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Block) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE publishers SET Blocked = 1 WHERE PublisherIndex = @PublisherIndex"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Untrusted) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE publishers SET Untrusted = 1 WHERE PublisherIndex = @PublisherIndex"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
            }
    
            "FilePublisher" {
                if ($UserMode) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_publishers SET TrustedUserMode = 1 WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey2) | Out-Null
                    $Command.Parameters.AddWithValue("MinimumAllowedVersion",$PrimaryKey3) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Driver) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_publishers SET TrustedDriver = 1 WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey2) | Out-Null
                    $Command.Parameters.AddWithValue("MinimumAllowedVersion",$PrimaryKey3) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Block) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_publishers SET Blocked = 1 WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey2) | Out-Null
                    $Command.Parameters.AddWithValue("MinimumAllowedVersion",$PrimaryKey3) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Untrusted) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_publishers SET Untrusted = 1 WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey2) | Out-Null
                    $Command.Parameters.AddWithValue("MinimumAllowedVersion",$PrimaryKey3) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
                    $Command.ExecuteNonQuery()
                }
            }
    
            "LeafCertificate" {
                if ($UserMode) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET TrustedUserMode = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 1"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Driver) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET TrustedDriver = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 1"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Block) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET Blocked = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 1"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Untrusted) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET Untrusted = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 1"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
            }
    
            "PcaCertificate" {
                if ($UserMode) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET TrustedUserMode = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 0"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Driver) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET TrustedDriver = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 0"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Block) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET Blocked = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 0"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Untrusted) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE certificates SET Untrusted = 1 WHERE TBSHash = @TBSHash AND IsLeaf = 0"
                    $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                    $Command.ExecuteNonQuery()
                }
            }
    
            "FilePath" {
                #TODO
                #Write-Verbose "FilePath rules have not yet been implemented."
            }
    
            "FileName" {
                if ($UserMode) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_names SET TrustedUserMode = 1 WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$PrimaryKey2) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Driver) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_names SET TrustedDriver = 1 WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$PrimaryKey2) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Block) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_names SET Blocked = 1 WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$PrimaryKey2) | Out-Null
                    $Command.ExecuteNonQuery()
                }
                if ($Untrusted) {
                    $Command = $Connection.CreateCommand()
                    $Command.Commandtext = "UPDATE file_names SET Untrusted = 1 WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
                    $Command.Parameters.AddWithValue("FileName",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("SpecificFileNameLevel",$PrimaryKey2) | Out-Null
                    $Command.ExecuteNonQuery()
                }
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

function Update-WDACTrustPoliciesAndComment {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrimaryKey1,
        $PrimaryKey2,
        $PrimaryKey3,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Level,
        [bool]$Block,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        $Comment,
        [bool]$MSIorScripts,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        switch ($Level) {
            "Hash" {
                if ($MSIorScripts) {
                    #TODO
                } else {
                    $Command = $Connection.CreateCommand()
                    if ($Block) {
                        $Command.Commandtext = "UPDATE apps SET BlockingPolicyID = @PolicyGUID, Comment = @Comment WHERE Sha256FlatHash = @Sha256FlatHash"
                    } else {
                        $Command.Commandtext = "UPDATE apps SET AllowedPolicyID = @PolicyGUID, Comment = @Comment WHERE Sha256FlatHash = @Sha256FlatHash"
                    }
                    $Command.Parameters.AddWithValue("Sha256FlatHash",$PrimaryKey1) | Out-Null
                    $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
                    $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
                    $Command.ExecuteNonQuery()
                }
            }
    
            "Publisher" {
                $Command = $Connection.CreateCommand()
                if ($Block) {
                    $Command.Commandtext = "UPDATE publishers SET BlockingPolicyID = @PolicyGUID, Comment = @Comment WHERE PublisherIndex = @PublisherIndex"
                } else {
                    $Command.Commandtext = "UPDATE publishers SET AllowedPolicyID = @PolicyGUID, Comment = @Comment WHERE PublisherIndex = @PublisherIndex"
                }
                $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
                $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
                $Command.ExecuteNonQuery()
            }
    
            "FilePublisher" {
                $Command = $Connection.CreateCommand()
                if ($Block) {
                    $Command.Commandtext = "UPDATE file_publishers SET BlockingPolicyID = @PolicyGUID, Comment = @Comment WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion"
                } else {
                    $Command.Commandtext = "UPDATE file_publishers SET AllowedPolicyID = @PolicyGUID, Comment = @Comment WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND MinimumAllowedVersion = @MinimumAllowedVersion"
                }
                $Command.Parameters.AddWithValue("PublisherIndex",$PrimaryKey1) | Out-Null
                $Command.Parameters.AddWithValue("FileName",$PrimaryKey2) | Out-Null
                $Command.Parameters.AddWithValue("MinimumAllowedVersion",$PrimaryKey3) | Out-Null
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
                $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
                $Command.ExecuteNonQuery()
            }
    
            "LeafCertificate" {
                $Command = $Connection.CreateCommand()
                if ($Block) {
                    $Command.Commandtext = "UPDATE certificates SET BlockingPolicyID = @PolicyGUID, Comment = @Comment WHERE TBSHash = @TBSHash AND IsLeaf = 1"
                } else {
                    $Command.Commandtext = "UPDATE certificates SET AllowedPolicyID = @PolicyGUID, Comment = @Comment WHERE TBSHash = @TBSHash AND IsLeaf = 1"
                }
                $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
                $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
                $Command.ExecuteNonQuery()
            }
    
            "PcaCertificate" {
                $Command = $Connection.CreateCommand()
                if ($Block) {
                    $Command.Commandtext = "UPDATE certificates SET BlockingPolicyID = @PolicyGUID, Comment = @Comment WHERE TBSHash = @TBSHash AND IsLeaf = 0"
                } else {
                    $Command.Commandtext = "UPDATE certificates SET AllowedPolicyID = @PolicyGUID, Comment = @Comment WHERE TBSHash = @TBSHash AND IsLeaf = 0"
                }
                $Command.Parameters.AddWithValue("TBSHash",$PrimaryKey1) | Out-Null
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
                $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
                $Command.ExecuteNonQuery()
            }
    
            "FilePath" {
                #TODO
                #Write-Verbose "FilePath rules have not yet been implemented."
            }
    
            "FileName" {
                $Command = $Connection.CreateCommand()
                if ($Block) {
                    $Command.Commandtext = "UPDATE file_names SET BlockingPolicyID = @PolicyGUID, Comment = @Comment WHERE FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
                } else {
                    $Command.Commandtext = "UPDATE file_names SET AllowedPolicyID = @PolicyGUID, Comment = @Comment WHERE FileName = @FileName  AND SpecificFileNameLevel = @SpecificFileNameLevel"
                }
                $Command.Parameters.AddWithValue("FileName",$PrimaryKey1) | Out-Null
                $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
                $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
                $Command.Parameters.AddWithValue("SpecificFileNameLevel",$PrimaryKey2) | Out-Null
                $Command.ExecuteNonQuery()
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

function Test-AppBlocked {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Hash","FlatHash")]
        [string]$SHA256FlatHash,
        [Alias("Levels")]
        $AllPossibleLevels,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $AllPossibleLevels) {
        $AllPossibleLevels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    } else {
        foreach ($LevelProvided in $AllPossibleLevels) {
            if (-not (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher") -contains $LevelProvided)) {
                throw "Please provide one or more of the following levels: Hash,FilePath,FileName,LeafCertificate,PcaCertificate,Publisher,FilePublisher"
            }
        }
    }
    $SpecificFileNameLevels = @("OriginalFileName","InternalName","FileDescription","ProductName","PackageFamilyName")

    try {
        $AppInstance = Get-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop
        $CertInfo = Expand-WDACApp -SHA256FlatHash $SHA256FlatHash -Connection $Connection -ErrorAction Stop

        function Get-BlockedInstanceFilePublishers {
            [CmdletBinding()]
            Param (
                [ValidateNotNullOrEmpty()]
                [Parameter(Mandatory=$true)]
                $FilePublishers,
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

                if ($Encompasses -and ($FilePublisher.Blocked -eq $true)) {
                    return $true
                }
            }
        }

        switch ($AllPossibleLevels) {
            "Hash" {
                if ($AppInstance.Blocked -eq $true) {
                    return $true
                }
            }
            "FilePath" {<#TODO#>}
            "FileName" {
                if ($AppInstance.OriginalFileName -or $AppInstance.InternalName -or $AppInstance.FileDescription -or $AppInstance.ProductName -or $AppInstance.PackageFamilyName) {
                    switch ($SpecificFileNameLevels) {

                        "OriginalFileName" {
                            if ($AppInstance.OriginalFileName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.OriginalFileName -SpecificFileNameLevel "OriginalFileName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if ($TempFileName.Blocked -eq $true) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "InternalName" {
                            if ($AppInstance.InternalName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.InternalName -SpecificFileNameLevel "InternalName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if ($TempFileName.Blocked -eq $true) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "FileDescription" {
                            if ($AppInstance.FileDescription) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.FileDescription -SpecificFileNameLevel "FileDescription" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if ($TempFileName.Blocked -eq $true) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "ProductName" {
                            if ($AppInstance.ProductName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.ProductName -SpecificFileNameLevel "ProductName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if ($TempFileName.Blocked -eq $true) {
                                        return $true
                                    }
                                }
                            }
                        }
                        "PackageFamilyName" {
                            if ($AppInstance.PackageFamilyName) {
                                $TempFileName = Get-WDACFileName -FileName $AppInstance.PackageFamilyName -SpecificFileNameLevel "PackageFamilyName" -Connection $Connection -ErrorAction Stop
                                if ($TempFileName) {
                                    if ($TempFileName.Blocked -eq $true) {
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
                        if ($LeafCertificate.Blocked -eq $true) {
                            return $true
                        }
                    }
                }
            }
            "PcaCertificate" {
                if ($CertInfo) {
                    foreach ($PcaCertificate in $CertInfo.PcaCert) {
                        if ($PcaCertificate.Blocked -eq $true) {
                            return $true
                        }
                    }
                }
            }
            "Publisher" {
                if ($CertInfo) {
                    foreach ($LeafCertificate in $CertInfo.LeafCert) {
                        if ($LeafCertificate.CommonName -and $LeafCertificate.ParentCertTBSHash) {
                            $TempPublisher = Get-WDACPublisher -LeafCertCN $LeafCertificate.CommonName -PcaCertTBSHash $LeafCertificate.ParentCertTBSHash -Connection $Connection -ErrorAction Stop
                            if ($TempPublisher) {
                                if ($TempPublisher.Blocked -eq $true) {
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
                            $TempPublisher = Get-WDACPublisher -LeafCertCN $LeafCertificate.CommonName -PcaCertTBSHash $LeafCertificate.ParentCertTBSHash -Connection $Connection -ErrorAction Stop
                            if ($TempPublisher.PublisherIndex) {
                                switch ($SpecificFileNameLevels) {
                                    "OriginalFileName" {
                                        if ($AppInstance.OriginalFileName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.OriginalFileName -SpecificFileNameLevel "OriginalFileName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-BlockedInstanceFilePublishers -FilePublishers $TempFilePublishers -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "InternalName" {
                                        if ($AppInstance.InternalName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.InternalName -SpecificFileNameLevel "InternalName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-BlockedInstanceFilePublishers -FilePublishers $TempFilePublishers -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "FileDescription" {
                                        if ($AppInstance.FileDescription) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.FileDescription -SpecificFileNameLevel "FileDescription" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-BlockedInstanceFilePublishers -FilePublishers $TempFilePublishers -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "ProductName" {
                                        if ($AppInstance.ProductName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.ProductName -SpecificFileNameLevel "ProductName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-BlockedInstanceFilePublishers -FilePublishers $TempFilePublishers -FileVersion $AppInstance.FileVersion) {
                                                    return $true
                                                }
                                            }
                                        }
                                    }
                                    "PackageFamilyName" {
                                        if ($AppInstance.PackageFamilyName) {
                                            $TempFilePublishers = Get-WDACFilePublishers -PublisherIndex $TempPublisher.PublisherIndex -FileName $AppInstance.PackageFamilyName -SpecificFileNameLevel "PackageFamilyName" -Connection $Connection -ErrorAction Stop
                                            if ($TempFilePublishers) {
                                                if (Get-BlockedInstanceFilePublishers -FilePublishers $TempFilePublishers -FileVersion $AppInstance.FileVersion) {
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

function Test-AppBlockedStatusAllLevels {
    [CmdletBinding()]
    Param (   
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Hash","FlatHash")]
        [string]$SHA256FlatHash,
        [Alias("Levels")]
        $AllPossibleLevels,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not $AllPossibleLevels) {
        $AllPossibleLevels = @("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher")
    } else {
        foreach ($LevelProvided in $AllPossibleLevels) {
            if (-not (@("Hash","FilePath","FileName","LeafCertificate","PcaCertificate","Publisher","FilePublisher") -contains $LevelProvided)) {
                throw "Please provide one or more of the following levels: Hash,FilePath,FileName,LeafCertificate,PcaCertificate,Publisher,FilePublisher"
            }
        }
    }

    try {
        $Result = [PSCustomObject]@{}
        $ResultHashTable = @{}
    
        foreach ($Level in $AllPossibleLevels) {
            $ResultHashTable.Add($Level,$false)
            if (Test-AppBlocked -SHA256FlatHash $SHA256FlatHash -AllPossibleLevels $Level -Connection $Connection -ErrorAction Stop) {
                $ResultHashTable[$Level] = $true
            }
        }
        
        $Result | Add-Member -NotePropertyMembers $ResultHashTable -PassThru | Out-Null
        return $Result
    } catch {
        throw $_
    }   
}