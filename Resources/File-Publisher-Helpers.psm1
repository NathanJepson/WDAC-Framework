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

function Test-ValidVersionNumber {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$VersionNumber
    )

    return ($VersionNumber -match "^(0|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))(0|(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))){3}$")
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

function Format-SQLResult {
#This converts all PSObject members of type [System.DBNull] to $null
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [PSCustomObject[]]$Object
    )

    for ($i=0; $i -lt $Object.Count; $i++) {
        foreach ($Property in $Object[$i].PSObject.Properties) {
            if ($Property.TypeNameOfValue -eq [System.DBNull]) {
                $Object[$i].($Property.Name) = $null
            }
        }
    }
    
    return $Object
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
        [string]$SpecificFileNameLevel,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO policy_file_publisher_options (PolicyGUID,FileName,PublisherIndex,SpecificFileNameLevel) values (@PolicyGUID,@FileName,@PublisherIndex,@SpecificFileNameLevel)"
            $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null 
            $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
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
        [string]$SpecificFileNameLevel,
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
        $Command.Commandtext = "Select * from policy_file_publisher_options WHERE PolicyGUID = @PolicyGUID AND FileName = @FileName AND PublisherIndex = @PublisherIndex AND SpecificFileNameLevel = @SpecificFileNameLevel;"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    PolicyGUID = $Reader["PolicyGUID"];
                    FileName = $Reader["FileName"];
                    PublisherIndex = $Reader["PublisherIndex"];
                    SpecificFileNameLevel = $Reader["SpecificFileNameLevel"];
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
        [string]$SpecificFileNameLevel,
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
            $Command.Commandtext = "UPDATE policy_file_publisher_options SET MinimumTolerableMinimum = @MinimumTolerableMinimum WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND PolicyGUID = @PolicyGUID AND SpecificFileNameLevel = @SpecificFileNameLevel"
            $Command.Parameters.AddWithValue("MinimumTolerableMinimum",$NewValue) | Out-Null
        }
        else {
            $Command.Commandtext = "UPDATE policy_file_publisher_options SET MinimumAllowedVersionPivot = @MinimumAllowedVersionPivot WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND PolicyGUID = @PolicyGUID AND SpecificFileNameLevel = @SpecificFileNameLevel"
            $Command.Parameters.AddWithValue("MinimumAllowedVersionPivot",$NewValue) | Out-Null
        }
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
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
        [string]$SpecificFileNameLevel,
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
        $Command.Commandtext = "INSERT INTO file_publisher_options (FileName,PublisherIndex,VersioningType,SpecificFileNameLevel) values (@FileName,@PublisherIndex,@VersioningType,@SpecificFileNameLevel)"
            $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
            $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
            $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
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
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SpecificFileNameLevel,
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
        $Command.Commandtext = "Select * from file_publisher_options WHERE FileName = @FileName AND PublisherIndex = @PublisherIndex AND SpecificFileNameLevel = @SpecificFileNameLevel;"
        $Command.Parameters.AddWithValue("FileName",$FileName) | Out-Null
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
        $Command.Parameters.AddWithValue("SpecificFileNameLevel",$SpecificFileNameLevel) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
   
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    FileName = $Reader["FileName"];
                    PublisherIndex = $Reader["PublisherIndex"];
                    SpecificFileNameLevel = $Reader["SpecificFileNameLevel"];
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
        [string]$SpecificFileNameLevel,
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
            $Command.Commandtext = "UPDATE file_publisher_options SET MinimumTolerableMinimum = @MinimumTolerableMinimum WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
            $Command.Parameters.AddWithValue("MinimumTolerableMinimum",$NewValue) | Out-Null
        }
        else {
            $Command.Commandtext = "UPDATE file_publisher_options SET MinimumAllowedVersionPivot = @MinimumAllowedVersionPivot WHERE PublisherIndex = @PublisherIndex AND FileName = @FileName AND SpecificFileNameLevel = @SpecificFileNameLevel"
            $Command.Parameters.AddWithValue("MinimumAllowedVersionPivot",$NewValue) | Out-Null
        }
        $Command.Parameters.AddWithValue("PublisherIndex",$PublisherIndex) | Out-Null
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

function Get-FileVersionPrompt {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$Prompt,
        $CurrentVersionNum,
        $FileVersionInfo
    )

    Write-Host ($Prompt)
    Write-Host("Enter VersionNumber [OR] `"k`" to use Current App FileVersion [OR] `"0`" for 0.0.0.0 [OR] `"f`" for FilePublisher info")
    Write-Host("(Version numbers are from 0.0.0.0 to 65535.65535.65535.65535)")
    $VersionNumber = Read-Host -Prompt "Selection"

    while (-not ( (Test-ValidVersionNumber $VersionNumber) -or ($VersionNumber -eq 0) -or ($VersionNumber -eq "0") -or ($VersionNumber.ToLower() -eq "k"))) {
        if ($VersionNumber.ToLower() -eq "f") {
            Write-Host $FileVersionInfo
            $VersionNumber = Read-Host -Prompt "Selection"
            continue
        }
        Write-Host "Not a valid version number. Enter a version from 0.0.0.0 to 65535.65535.65535.65535"
        Write-Host "Also, no leading zeroes except for when a number itself is 0."
        $VersionNumber = Read-Host -Prompt "Selection"
    }

    if ( ($VersionNumber -eq "0") -or ($VersionNumber -eq 0)) {
        $VersionNumber = "0.0.0.0"
    } elseif ($VersionNumber.ToLower() -eq "k") {
        return $CurrentVersionNum
    }

    return $VersionNumber
}

function Get-FileVersionOldAndNewPrompt {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$Prompt,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PreviousVersionNum,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$CurrentVersionNum,
        $FileVersionInfo
    )

    Write-Host ($Prompt)
    Write-Host("Enter `"k`" to keep previous FileVersion $PreviousVersionNum [OR] `"n`" to use new FileVersion $CurrentVersionNum [OR] `"f`" for FilePublisher info")
    $VersionNumber = Read-Host -Prompt "Selection"

    while (-not ( ($VersionNumber.ToLower() -eq "n") -or ($VersionNumber.ToLower() -eq "k"))) {
        Write-Host "Please select `"k`" or `"n`" "
        $VersionNumber = Read-Host -Prompt "Selection"
        if ($VersionNumber.ToLower() -eq "f") {
            Write-Host $FileVersionInfo
            $VersionNumber = Read-Host -Prompt "Selection"
            continue
        }
    }

    if ($VersionNumber.ToLower() -eq "k") {
        return $PreviousVersionNum
    } elseif ($VersionNumber.ToLower() -eq "n") {
        return $CurrentVersionNum
    } else {
        throw "Error 1899300: Please reach out to the developer to fix this issue."
    }
}