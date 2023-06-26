function Import-SQLite {
    
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$SqliteAssembly
    )

    if (-not $SqliteAssembly) {
        try {
            $SqliteAssembly = (Get-LocalStorageJSON)."SqliteAssembly"
            if (-not $SqliteAssembly) {
                throw "No valid value for Sqlite binary provided from local storage."
            }
        } catch {
            Write-Error $_
            Write-Warning "Unable to read or process the file path for the Sqlite binary."
            return
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
        Write-Verbose $_
        Write-Error "This Sqlite binary is not supported in this version of PowerShell.";
        return;
    } catch {
        Write-Verbose $_
        Write-Error "Could not load the Sqlite binary. Failure to create database.";
        return;
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

function New-SqliteWDACGroupRow {
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
        $Command.Parameters.AddWithValue("GroupName",$GroupName)
        $Command.ExecuteNonQuery()
        $Connection.close()
    } catch {
        throw $_
    }
}