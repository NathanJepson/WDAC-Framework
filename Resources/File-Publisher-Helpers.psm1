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

function Add-PolicyFilePublisherOptions {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$VersioningType,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO policy_file_publisher_options (PolicyGUID,FileName,PublisherIndex,VersioningType) values (@PolicyGUID,@FileName,@PublisherIndex,@VersioningType)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null 
            $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
            $Command.Parameters.AddWithValue("VersioningType",$VersioningType) | Out-Null
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

function Get-PolicyFilePublisherOptions {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
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
        $Command.Commandtext = "Select * from policy_file_publisher_options WHERE PolicyGUID = @PolicyGUID AND FileName = @FileName AND PublisherIndex = @PublisherIndex;"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    PolicyGUID = $Reader["PolicyGUID"];
                    FileName = $Reader["FileName"];
                    PublisherIndex = $Reader["PublisherIndex"];
                    VersioningType = $Reader["VersioningType"];
                    MinimumAllowedVersionPivot = $Reader["MinimumAllowedVersionPivot"];
                    MinimumTolerableMinimum = $Reader["MinimumTolerableMinimum"]
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

function Edit-PolicyFilePublisherOptions {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("NewMinimum","VersionNumber","NewVersion","MinimumAllowedVersion","Value")]
        [string]$NewValue,
        [Alias("TolerableMinimum")]
        [switch]$MinimumTolerableMinimum,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        
        if ($MinimumTolerableMinimum) {
            $Command.Commandtext = "UPDATE policy_file_publisher_options SET MinimumTolerableMinimum = @MinimumTolerableMinimum WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND PolicyGUID = @PolicyGUID"
            $Command.Parameters.AddWithValue("MinimumTolerableMinimum",$NewValue) | Out-Null
        }
        else {
            $Command.Commandtext = "UPDATE policy_file_publisher_options SET MinimumAllowedVersionPivot = @MinimumAllowedVersionPivot WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND PolicyGUID = @PolicyGUID"
            $Command.Parameters.AddWithValue("MinimumAllowedVersionPivot",$NewValue) | Out-Null
        }
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
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

function Add-FilePublisherOptions {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$VersioningType,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO file_publisher_options (FileName,PublisherIndex,VersioningType) values (@FileName,@PublisherIndex,@VersioningType)"
            $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
            $Command.Parameters.AddWithValue("VersioningType",$VersioningType) | Out-Null
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

function Get-FilePublisherOptions {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
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
        $Command.Commandtext = "Select * from file_publisher_options WHERE FileName = @FileName AND PublisherIndex = @PublisherIndex;"
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    FileName = $Reader["FileName"];
                    PublisherIndex = $Reader["PublisherIndex"];
                    VersioningType = $Reader["VersioningType"];
                    MinimumAllowedVersionPivot = $Reader["MinimumAllowedVersionPivot"];
                    MinimumTolerableMinimum = $Reader["MinimumTolerableMinimum"]
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

function Edit-FilePublisherOptions {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$PublisherIndex,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("NewMinimum","VersionNumber","NewVersion","MinimumAllowedVersion","Value")]
        [string]$NewValue,
        [Alias("TolerableMinimum")]
        [switch]$MinimumTolerableMinimum,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        
        if ($MinimumTolerableMinimum) {
            $Command.Commandtext = "UPDATE file_publisher_options SET MinimumTolerableMinimum = @MinimumTolerableMinimum WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName"
            $Command.Parameters.AddWithValue("MinimumTolerableMinimum",$NewValue) | Out-Null
        }
        else {
            $Command.Commandtext = "UPDATE file_publisher_options SET MinimumAllowedVersionPivot = @MinimumAllowedVersionPivot WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName"
            $Command.Parameters.AddWithValue("MinimumAllowedVersionPivot",$NewValue) | Out-Null
        }
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
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

function Add-PolicyVersioningOptions {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$VersioningType,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO policy_versioning_options (PolicyGUID,VersioningType) values (@PolicyGUID,@VersioningType)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            $Command.Parameters.AddWithValue("VersioningType",$VersioningType) | Out-Null
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

function Get-PolicyVersioningOptions {
    [cmdletbinding()]
    param (
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
        $Command.Commandtext = "Select * from policy_versioning_options WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    PolicyGUID = $Reader["PolicyGUID"];
                    VersioningType = $Reader["VersioningType"]
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