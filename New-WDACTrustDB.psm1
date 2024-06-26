$ThisIsASignedModule = $false
if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\JSON-LocalStorageTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\JSON-LocalStorageTools.psm1")
}

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

    if ($ThisIsASignedModule) {
        Write-Verbose "The current file is in the SignedModules folder."
    }

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
        SHA1AuthenticodeHash TEXT,
        SHA256PageHash TEXT,
        SHA1PageHash TEXT,
        SHA256SipHash Text,
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
        FailedWHQL Integer,
        Untrusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Skipped Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        BlockingPolicyID Text COLLATE NOCASE,
        AllowedPolicyID Text COLLATE NOCASE,
        DeferredPolicyIndex Integer,
        Comment Text,
        AppIndex Integer UNIQUE NOT NULL,
        RequestedSigningLevel Text,
        ValidatedSigningLevel Text,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE msi_or_script (
        SHA256FlatHash TEXT PRIMARY KEY,
        SHA1FlatHash TEXT,
        TimeDetected TEXT NOT NULL,
        FirstDetectedPath TEXT NOT NULL,
        FirstDetectedUser TEXT,
        FirstDetectedProcessID Integer,
        SHA256AuthenticodeHash TEXT,
        SHA256SipHash Text,
        UserWriteable Integer DEFAULT 0 NOT NULL,
        Signed Text,
        OriginDevice TEXT NOT NULL,
        EventType Text,
        AppIndex Integer UNIQUE NOT NULL,
        Untrusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Skipped Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        BlockingPolicyID Text COLLATE NOCASE,
        AllowedPolicyID Text COLLATE NOCASE,
        DeferredPolicyIndex Integer,
        Comment Text,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE signers (
        AppIndex INTEGER NOT NULL,
        SignatureIndex INTEGER NOT NULL,
        CertificateTBSHash TEXT NOT NULL,
        SignatureType TEXT,
        PageHash Integer,
        Flags Integer,
        PolicyBits Integer,
        ValidatedSigningLevel Text,
        VerificationError Text,
        FOREIGN KEY(AppIndex) REFERENCES apps(AppIndex) ON DELETE CASCADE,
        FOREIGN KEY(CertificateTBSHash) REFERENCES certificates(TBSHash) ON DELETE CASCADE,
        PRIMARY KEY(AppIndex,SignatureIndex)
    );

    CREATE TABLE signers_msi_or_script (
        AppIndex INTEGER NOT NULL,
        SignatureIndex INTEGER NOT NULL,
        CertificateTBSHash TEXT NOT NULL,
        FOREIGN KEY(AppIndex) REFERENCES msi_or_script(AppIndex) ON DELETE CASCADE,
        FOREIGN KEY(CertificateTBSHash) REFERENCES certificates(TBSHash) ON DELETE CASCADE,
        PRIMARY KEY(AppIndex,SignatureIndex)
    );
    
    CREATE TABLE certificates (
        TBSHash Text PRIMARY KEY,
        CommonName Text NOT NULL,
        ParentCertTBSHash Text,
        NotValidBefore Text,
        NotValidAfter Text,
        Untrusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        AllowedPolicyID Text COLLATE NOCASE,
        DeferredPolicyIndex Integer,
        Comment Text,
        BlockingPolicyID Text COLLATE NOCASE,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT,
        FOREIGN KEY(ParentCertTBSHash) REFERENCES certificates(TBSHash) ON DELETE SET NULL
    );
    
    CREATE TABLE publishers (
        LeafCertCN Text NOT NULL,
        PcaCertTBSHash Text NOT NULL,
        Untrusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        AllowedPolicyID Text COLLATE NOCASE,
        DeferredPolicyIndex Integer,
        Comment Text,
        BlockingPolicyID Text COLLATE NOCASE,
        PublisherIndex Integer UNIQUE NOT NULL,
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT,
        FOREIGN KEY(PcaCertTBSHash) REFERENCES certificates(TBSHash) ON DELETE CASCADE,
        PRIMARY KEY(PcaCertTBSHash,LeafCertCN)
    );

    CREATE TABLE file_publishers (
        PublisherIndex Integer NOT NULL,
        Untrusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        AllowedPolicyID Text COLLATE NOCASE,
        DeferredPolicyIndex Integer,
        Comment Text,
        BlockingPolicyID Text COLLATE NOCASE,
        MinimumAllowedVersion Text NOT NULL,
        MaximumAllowedVersion Text,
        FileName Text NOT NULL,
        SpecificFileNameLevel Text NOT NULL,
        PRIMARY KEY(PublisherIndex,FileName,MinimumAllowedVersion,SpecificFileNameLevel),
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT,
        FOREIGN KEY(PublisherIndex) REFERENCES publishers(PublisherIndex) ON DELETE CASCADE
    );

    CREATE TABLE file_names (
        FileName Text NOT NULL,
        SpecificFileNameLevel Text NOT NULL,
        Untrusted Integer DEFAULT 0 NOT NULL,
        TrustedDriver Integer DEFAULT 0 NOT NULL,
        TrustedUserMode Integer DEFAULT 0 NOT NULL,
        Staged Integer DEFAULT 0 NOT NULL,
        Revoked Integer DEFAULT 0 NOT NULL,
        Deferred Integer DEFAULT 0 NOT NULL,
        Blocked Integer DEFAULT 0 NOT NULL,
        AllowedPolicyID Text COLLATE NOCASE,
        DeferredPolicyIndex Integer,
        Comment Text,
        BlockingPolicyID Text COLLATE NOCASE,
        PRIMARY KEY(FileName,SpecificFileNameLevel),
        FOREIGN KEY(AllowedPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(BlockingPolicyID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT
    );

    CREATE TABLE file_publisher_options (
        FileName Text NOT NULL,
        PublisherIndex Integer NOT NULL,
        VersioningType Integer NOT NULL,
        MinimumAllowedVersionPivot Text,
        MinimumTolerableMinimum Text,
        SpecificFileNameLevel Text NOT NULL,
        FOREIGN KEY(PublisherIndex) REFERENCES publishers(PublisherIndex) ON DELETE CASCADE,
        PRIMARY KEY(PublisherIndex,FileName,SpecificFileNameLevel)
    );

    CREATE TABLE policy_file_publisher_options (
        FileName Text NOT NULL,
        PublisherIndex Integer NOT NULL,
        PolicyGUID Text NOT NULL COLLATE NOCASE,
        MinimumAllowedVersionPivot Text,
        MinimumTolerableMinimum Text,
        SpecificFileNameLevel Text NOT NULL,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT,
        FOREIGN KEY(PublisherIndex) REFERENCES publishers(PublisherIndex) ON DELETE CASCADE,
        PRIMARY KEY (FileName,PublisherIndex,PolicyGUID,SpecificFileNameLevel)
    );
    
    CREATE TABLE policy_versioning_options (
        PolicyGUID Text COLLATE NOCASE PRIMARY KEY,
        VersioningType Integer NOT NULL,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE CASCADE
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
        PolicyGUID Text NOT NULL COLLATE NOCASE PRIMARY KEY,
        PolicyID Text,
        PolicyHash Text,
        PolicyName Text UNIQUE NOT NULL,
        PolicyVersion Text NOT NULL,
        ParentPolicyGUID Text COLLATE NOCASE,
        BaseOrSupplemental INTEGER DEFAULT 0 NOT NULL,
        IsSigned Integer DEFAULT 0 NOT NULL,
        AuditMode Integer DEFAULT 1 NOT NULL,
        IsPillar Integer DEFAULT 0 NOT NULL,
        OriginLocation Text NOT NULL,
        OriginLocationType Text NOT NULL,
        LastDeployedPolicyVersion Text,
        LastSignedVersion Text,
        LastUnsignedVersion Text,
        DeployedSigned Integer DEFAULT 0 NOT NULL,
        FOREIGN KEY (ParentPolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE policy_assignments (
        GroupName Text NOT NULL,
        PolicyGUID Text NOT NULL COLLATE NOCASE,
        PRIMARY KEY(GroupName,PolicyGUID),
        FOREIGN KEY(GroupName) REFERENCES groups(GroupName) ON DELETE RESTRICT,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE ad_hoc_policy_assignments (
        PolicyGUID Text NOT NULL COLLATE NOCASE,
        DeviceName Text NOT NULL COLLATE NOCASE,
        PRIMARY KEY(PolicyGUID,DeviceName),
        FOREIGN KEY(DeviceName) REFERENCES devices(DeviceName) ON DELETE CASCADE,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE RESTRICT
    );

    CREATE TABLE devices (
        DeviceName Text COLLATE NOCASE PRIMARY KEY,
        AllowedGroup Text,
        UpdateDeferring Integer DEFAULT 0,
        processor_architecture Text,
        FOREIGN KEY(AllowedGroup) REFERENCES groups(GroupName) ON DELETE RESTRICT
    );

    CREATE TABLE deferred_policies (
        DeferredPolicyIndex Integer PRIMARY KEY,
        DeferredDevicePolicyGUID Text NOT NULL COLLATE NOCASE,
        PolicyVersion Text,
        IsSigned Integer DEFAULT 0 NOT NULL
    );

    CREATE TABLE deferred_policies_assignments (
        DeferredPolicyIndex Integer NOT NULL,
        DeviceName Text NOT NULL COLLATE NOCASE,
        comment Text,
        FOREIGN KEY(DeferredPolicyIndex) REFERENCES deferred_policies(DeferredPolicyIndex) ON DELETE RESTRICT,
        FOREIGN KEY(DeviceName) REFERENCES devices(DeviceName) ON DELETE RESTRICT,
        PRIMARY KEY(DeferredPolicyIndex,DeviceName)
    );

    CREATE TABLE first_signed_policy_deployments (
        PolicyGUID Text NOT NULL COLLATE NOCASE,
        DeviceName Text NOT NULL COLLATE NOCASE,
        PRIMARY KEY(PolicyGUID,DeviceName),
        FOREIGN KEY(DeviceName) REFERENCES devices(DeviceName) ON DELETE CASCADE,
        FOREIGN KEY(PolicyGUID) REFERENCES policies(PolicyGUID) ON DELETE CASCADE
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

    try {
        New-Item -Path $Destination -Name $DBName -ErrorAction Stop | Out-Null
        $sDatabaseConnectionString=[string]::Format("data source={0};Foreign Key Constraints=On",$Database)
        $oSQLiteDBConnection = New-Object System.Data.SQLite.SQLiteConnection
        $oSQLiteDBConnection.ConnectionString = $sDatabaseConnectionString
        $oSQLiteDBConnection.open()
    
        $oSQLiteDBCommand=$oSQLiteDBConnection.CreateCommand()
        $oSQLiteDBCommand.Commandtext=$MakeTables
        $oSQLiteDBCommand.CommandType = [System.Data.CommandType]::Text
        $oSQLiteDBCommand.ExecuteNonQuery()
    
        $oSQLiteDBConnection.close()
        Remove-Variable oSQLiteDBConnection -ErrorAction SilentlyContinue
        Write-Host "New trust database created successfully." -ForegroundColor Green
    } catch {
        Write-Verbose ($_ | Format-List -Property * | Out-String)
        throw $_
    }
}

Export-ModuleMember -Function New-WDACTrustDB