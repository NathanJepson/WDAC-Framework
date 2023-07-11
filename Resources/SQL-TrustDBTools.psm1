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
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        # if ($Transaction) {
        #     $Transaction.Rollback()
        # }
        throw $_
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
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($Reader) {
            $Reader.Close()
        }
        throw $_
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
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        throw $_
    }
}