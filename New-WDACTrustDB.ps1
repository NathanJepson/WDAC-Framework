function New-WDACTrustDB {
    <#
    .SYNOPSIS
    Creates a new WDAC trust database (storing audit events, trusted files, and groups / devices)
    
    .DESCRIPTION
    Creates a SQlite database in the specified destination and creates the relevant tables to store code integrity events / trusted files, certificates, and information about groups and devices within those groups.
    
    Author: Nathan Jepson
    License: MIT License

    .PARAMETER DBName
    Specifies the name of the database. Default name is "trust.db"

    .PARAMETER Destination
    Destination directory to save the new database.

    .PARAMETER SqliteAssembly
    Specify the filepath of the Sqlite .dll, in order to set / reset the SqliteAssembly local variable in the PowerShell module resources folder.

    .EXAMPLE
    Add-WDACTrustDB -Destination "C:\Users\JohnSmith\Documents\WDAC_Folder\" -SqliteAssembly "C:\Sqlite\sqlite-netFx46-binary-x64-2015-1.0.118.0\System.Data.SQLite.dll"

    .EXAMPLE
    Add-WDACTrustDB -Destination ".\" -SqliteAssembly "C:\Sqlite\sqlite-netFx46-binary-x64-2015-1.0.118.0\System.Data.SQLite.dll" -DBName "WDAC_Trust.db"

    .EXAMPLE
    Add-WDACTrustDB -Destination "C:\Users\JohnSmith\Documents\WDAC_Folder\"
    #>

    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$DBName = "trust.db",
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,
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

    $MakeTables = @'
    CREATE TABLE apps (
        SHA256FlatHash TEXT PRIMARY KEY,
        FileName TEXT NOT NULL,
        TimeDetected TEXT NOT NULL,
        FirstDetectedPath TEXT NOT NULL,
        FirstDetectedUser TEXT,
        FirstDetectedProcessID Integer,
        FirstDetectedProcessName TEXT NOT NULL,
        SHA256AuthenticodeHash TEXT NOT NULL,
        OriginDevice TEXT NOT NULL,
        EventType Text,
        SigningScenario Text,
        OriginalFileName Text,
        FileVersion Text,
        InternalName Text,
        FileDescription Text,
        ProductName Text,
        PackageFamilyName Text,
        UserWriteable Integer DEFAULT 0 NOT NULL,
        FailedWHQL Integer DEFAULT 0 NOT NULL,
        Trusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        BlockingPolicyID Text NOT NULL,
        AllowedPolicyID Text,
        Comment Text,
        AppIndex Integer UNIQUE NOT NULL,
        RequestedSigningLevel Text,
        ValidatedSigningLevel Text,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE msi_or_script (
        SHA256FlatHash TEXT PRIMARY KEY,
        TimeDetected TEXT NOT NULL,
        FirstDetectedPath TEXT NOT NULL,
        FirstDetectedUser TEXT,
        FirstDetectedProcessID Integer,
        SHA256AuthenticodeHash TEXT NOT NULL,
        UserWriteable Integer DEFAULT 0 NOT NULL,
        Signed Integer DEFAULT 0 NOT NULL,
        OriginDevice TEXT NOT NULL,
        EventType Text,
        AppIndex Integer UNIQUE NOT NULL,
        Trusted Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        BlockingPolicyID Text NOT NULL,
        AllowedPolicyID Text,
        Comment Text,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE signers (
        AppIndex INTEGER NOT NULL,
        SignatureIndex INTEGER NOT NULL,
        CertificateTBSHash TEXT NOT NULL,
        SignatureType TEXT,
        PageHash Integer DEFAULT 0 NOT NULL,
        Flags Integer,
        PolicyBits Integer,
        ValidatedSigningLevel Text,
        VerificationError Text,
        FOREIGN KEY(AppIndex) REFERENCES apps(AppIndex) ON DELETE CASCADE,
        FOREIGN KEY(AppIndex) REFERENCES msi_or_script(AppIndex) ON DELETE RESTRICT,
        FOREIGN KEY(CertificateTBSHash) REFERENCES certificates(TBSHash) ON DELETE CASCADE,
        PRIMARY KEY(AppIndex,SignatureIndex)
    );
    
    CREATE TABLE certificates (
        TBSHash Text PRIMARY KEY,
        CommonName Text NOT NULL,
        IsLeaf DEFAULT 1 NOT NULL,
        ParentCertTBSHash Text,
        NotValidBefore Text,
        NotValidAfter Text,
        FOREIGN KEY(ParentCertTBSHash) REFERENCES certificates(TBSHash) ON DELETE SET NULL
    );
    
    CREATE TABLE publishers (
        LeafCertCN Text NOT NULL,
        PcaCertTBSHash Text NOT NULL,
        Trusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        PublisherTBSHash Text NOT NULL,
        AllowedPolicyID Text,
        Comment Text,
        BlockingPolicyID Text,
        PublisherIndex Integer UNIQUE NOT NULL,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(PcaCertTBSHash) REFERENCES certificates(TBSHash) ON DELETE CASCADE,
        PRIMARY KEY(PcaCertTBSHash,LeafCertCN)
    );

    CREATE TABLE file_publishers (
        PublisherIndex Integer NOT NULL,
        AppIndex Integer NOT NULL,
        Trusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        AllowedPolicyID Text,
        Comment Text,
        BlockingPolicyID Text,
        MinimumAllowedVersion Text,
        MaximumAllowedVersion Text,
        OriginalFileName Text NOT NULL,
        PRIMARY KEY(PublisherIndex,AppIndex),
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(PublisherIndex) REFERENCES publishers(PublisherIndex) ON DELETE CASCADE
    );
    
    CREATE TABLE groups (
        GroupName Text PRIMARY KEY
    );

    CREATE TABLE group_mirrors (
        GroupName Text NOT NULL,
        MirroredGroupName Text NOT NULL,
        PRIMARY KEY(GroupName,MirroredGroupName),
        FOREIGN KEY(MirroredGroupName) REFERENCES groups(GroupName) ON DELETE CASCADE,
        FOREIGN KEY(GroupName) REFERENCES groups(GroupName) ON DELETE CASCADE
    );

    CREATE TABLE policies (
        PolicyGUID Text NOT NULL PRIMARY KEY,
        PolicyID Text,
        PolicyHash Text,
        PolicyName Text UNIQUE NOT NULL,
        PolicyVersion Text NOT NULL,
        ParentPolicyGUID Text,
        BaseOrSupplemental INTEGER DEFAULT 0 NOT NULL,
        IsSigned Integer DEFAULT 0 NOT NULL,
        AuditMode Integer DEFAULT 1 NOT NULL,
        IsPillar Integer DEFAULT 0 NOT NULL,
        OriginLocation Text NOT NULL,
        OriginLocationType Text NOT NULL,
        FOREIGN KEY (ParentPolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE policy_assignments (
        GroupName Text NOT NULL,
        PolicyGUID Text NOT NULL,
        PRIMARY KEY(GroupName,PolicyGUID),
        FOREIGN KEY(GroupName) REFERENCES groups(GroupName) ON DELETE RESTRICT,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE ad_hoc_policy_assignments (
        PolicyGUID Text NOT NULL,
        DeviceName Text NOT NULL,
        PRIMARY KEY(PolicyGUID,DeviceName),
        FOREIGN KEY(DeviceName) REFERENCES devices(DeviceName) ON DELETE CASCADE,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE devices (
        DeviceName Text PRIMARY KEY,
        AllowedGroup Text,
        UpdateDeferring Integer DEFAULT 0,
        DeferredPoliciesIndex Integer,
        FOREIGN KEY(AllowedGroup) REFERENCES groups(GroupName) ON DELETE RESTRICT,
        FOREIGN KEY(DeferredPoliciesIndex) REFERENCES deferred_policies(DeferredPoliciesIndex) ON DELETE RESTRICT
    );

    CREATE TABLE deferred_policies (
        DeferredPoliciesIndex Integer,
        DeferredDevicePolicyGUID Text,
        PolicyName Text NOT NULL,
        PolicyID Text,
        PolicyVersion Text NOT NULL,
        ParentPolicyGUID Text,
        BaseOrSupplemental INTEGER DEFAULT 0 NOT NULL,
        IsSigned Integer DEFAULT 0 NOT NULL,
        AuditMode Integer DEFAULT 1 NOT NULL,
        IsPillar Integer DEFAULT 0 NOT NULL,
        OriginLocation Text NOT NULL,
        OriginLocationType Text NOT NULL,
        PRIMARY KEY(DeferredPoliciesIndex)
    );
'@    
    $Database = Join-Path -Path $Destination -ChildPath $DBName
    if (Test-Path $Database) {
        Write-Warning "Database already exists.";
        return;
    }

    try {
        #This could throw off some EDR or anti-virus solutions
        [Reflection.Assembly]::LoadFile($SqliteAssembly)
    } catch [NotSupportedException] {
        Write-Verbose $_
        Write-Error "This Sqlite binary is not supported in this version of PowerShell.";
        return;
    } catch {
        Write-Verbose $_
        Write-Error "Could not load the Sqlite binary. Failure to create database.";
        return;
    }

    New-Item -Path $Destination -Name $DBName | Out-Null

    $sDatabaseConnectionString=[string]::Format("data source={0}",$Database)
    $oSQLiteDBConnection = New-Object System.Data.SQLite.SQLiteConnection
    $oSQLiteDBConnection.ConnectionString = $sDatabaseConnectionString
    $oSQLiteDBConnection.open()

    $oSQLiteDBCommand=$oSQLiteDBConnection.CreateCommand()
    $oSQLiteDBCommand.Commandtext=$MakeTables
    $oSQLiteDBCommand.CommandType = [System.Data.CommandType]::Text
    $oSQLiteDBCommand.ExecuteNonQuery()

    $oSQLiteDBConnection.close()
}