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

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

function Get-PolicyFileName {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $thePolicy = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $PolicyName = $thePolicy.PolicyName
        $VersionNumber = $thePolicy.PolicyVersion
        $FileName = ($PolicyName + "_v" + ($VersionNumber.replace('.','_')) + ".xml")
        return $FileName

    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }
}

function Get-FullPolicyPath {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
    $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"
    $FileName = Get-PolicyFileName -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

    if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
        return (Join-Path $WorkingPoliciesLocation -ChildPath $FileName)
    } else {
    #TODO: Other working policies directory types
    }

    return $null
}

function Receive-FileAsPolicy {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $WorkingPoliciesLocation = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Location"
    $WorkingPoliciesLocationType = (Get-LocalStorageJSON -ErrorAction Stop)."WorkingPoliciesDirectory"."Type"
    $NewFileName = Get-PolicyFileName -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

    if (-not $NewFileName) {
        throw "Cannot resolve new file name for Policy $PolicyGUID"
    }

    if ($WorkingPoliciesLocationType.ToLower() -eq "local") {
        Copy-Item $FilePath -Destination (Join-Path $WorkingPoliciesLocation -ChildPath $NewFileName) -Force -ErrorAction Stop
    } else {
    #TODO: Other working policies directory types
    }
}

function Get-PolicyXML {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        $PolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        [XML]$XMLFileContent = Get-Content -Path $PolicyPath -ErrorAction Stop
        return $XMLFileContent
    } catch {
        throw $_
    }
}

function Set-XMLPolicyVersion {
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
        $XML = Get-PolicyXML -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $XML.SiPolicy.VersionEx = $Version
        $XML.save((Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop))
    } catch {
        throw $_
    }
}