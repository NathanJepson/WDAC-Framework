function Add-WDACTrustDB {
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

    #TODO: Grab sqlite assembly path from LocalStorage if already present.
        #: Throw exception if not provided from storage or parameters.

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
            Staged Integer DEFAULT 0 NOT NULL,
            Revoked Integer DEFAULT 0 NOT NULL,
            Comment Text,
            BlockingPolicyID Text NOT NULL,
            AllowedPolicyID Text,
            AllowedGroup Text,
            AppIndex Integer UNIQUE NOT NULL,
            RequestedSigningLevel Text,
            ValidatedSigningLevel Text,
            FOREIGN KEY(AppIndex) REFERENCES signers(AppIndex) ON DELETE RESTRICT,
            FOREIGN KEY(AllowedGroup) REFERENCES groups(GroupName) ON DELETE RESTRICT,
            FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
            FOREIGN KEY(AppIndex) REFERENCES file_publishers(AppIndex) ON DELETE RESTRICT
        );

        CREATE TABLE signers (
            AppIndex TEXT NOT NULL,
            SignatureIndex TEXT NOT NULL,
            CertificateTBSHash TEXT NOT NULL,
            SignatureType TEXT,
            PageHash Integer DEFAULT 0 NOT NULL,
            Flags Integer,
            PolicyBits Integer,
            ValidatedSigningLevel Text,
            VerificationError Text,
            FOREIGN KEY(CertificateTBSHash) REFERENCES certificates(TBSHash) ON DELETE RESTRICT,
            PRIMARY KEY(AppIndex,SignatureIndex)
        );
        
        CREATE TABLE certificates (
            TBSHash Text PRIMARY KEY,
            CommonName Text NOT NULL,
            IsLeaf DEFAULT 1 NOT NULL,
            ParentCertTBSHash Text,
            NotValidBefore Text NOT NULL,
            NotValidAfter Text NOT NULL,
            FOREIGN KEY(ParentCertTBSHash) REFERENCES certificates(TBSHash) ON DELETE RESTRICT
        );
        
        CREATE TABLE publishers (
            LeafCertCN Text NOT NULL,
            PcaCertTBSHash Text NOT NULL,
            Trusted Integer DEFAULT 0 NOT NULL,
            Staged Integer DEFAULT 0 NOT NULL,
            Revoked Integer DEFAULT 0 NOT NULL,
            PublisherTBSHash Text NOT NULL,
            AllowedPolicyID Text,
            AllowedGroup Text,
            Comment Text,
            PublisherIndex Integer UNIQUE NOT NULL,
            FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
            FOREIGN KEY(PcaCertTBSHash) REFERENCES certificates(TBSHash) ON DELETE RESTRICT,
            FOREIGN KEY(AllowedGroup) REFERENCES groups(GroupName) ON DELETE RESTRICT,
            PRIMARY KEY(PcaCertTBSHash,LeafCertCN)
        );

        CREATE TABLE file_publishers (
            PublisherIndex Integer NOT NULL,
            AppIndex Text NOT NULL,
            PRIMARY KEY(PublisherIndex,AppIndex),
            FOREIGN KEY(PublisherIndex) REFERENCES publishers(PublisherIndex) ON DELETE RESTRICT
        )
        
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
        
        CREATE TABLE pillars (
            PillarName Text NOT NULL PRIMARY KEY,
            PolicyGUID Text
        );

        CREATE TABLE policies (
            PolicyGUID Text NOT NULL PRIMARY KEY,
            PolicyID Text,
            PolicyHash Text NOT NULL,
            PolicyName Text UNIQUE NOT NULL,
            PolicyVersion Text NOT NULL,
            ParentPolicyGUID Text,
            BaseOrSupplemental INTEGER DEFAULT 0 NOT NULL,
            IsSigned Integer DEFAULT 0 NOT NULL,
            AuditMode Integer DEFAULT 1 NOT NULL,
            OriginLocation Text NOT NULL,
            OriginLocationType Text NOT NULL,
            FOREIGN KEY (PolicyGUID) REFERENCES pillars(PolicyGUID) ON DELETE RESTRICT,
            FOREIGN KEY (ParentPolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
        );

        CREATE TABLE policy_assignments (
            GroupName Text NOT NULL,
            PolicyGUID Text NOT NULL,
            PRIMARY KEY(GroupName,PolicyGUID),
            FOREIGN KEY(GroupName) REFERENCES groups(GroupName) ON DELETE RESTRICT,
            FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
        );

        CREATE TABLE devices (
            DeviceName Text PRIMARY KEY,
            AllowedGroup Text,
            UpdateDeferring Integer DEFAULT 0,
            DeferredPoliciesIndex Integer,
            FOREIGN KEY(AllowedGroup) REFERENCES groups(GroupName) ON DELETE RESTRICT
        );

        CREATE TABLE deferred_policies (
            DeferredPoliciesIndex Integer,
            DeferredDevicePolicyGUID Text,
            PRIMARY KEY(DeferredPoliciesIndex,DeferredDevicePolicyGUID),
            FOREIGN KEY(DeferredPoliciesIndex) REFERENCES devices(DeferredPoliciesIndex) ON DELETE CASCADE,
            FOREIGN KEY(DeferredDevicePolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE CASCADE
        );
'@
    #TODO: Create a table to store information about deleted policies when PowerShell remoting fails (which policies could not be removed from the device)
    
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

    New-Item -Path $Destination -Name $DBName

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