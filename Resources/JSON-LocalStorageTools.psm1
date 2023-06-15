$StorageFile = Join-Path -Path $PSScriptRoot -ChildPath ".\LocalStorage.json"
$TestStorageFile = Join-Path -Path $PSScriptRoot -ChildPath ".\LocalStorageTest.json"
if (Test-Path $TestStorageFile) {
    $StorageFile = $TestStorageFile
}

function Get-LocalStorageJSON {
    $JSONObj = (Get-Content $StorageFile -Raw) | ConvertFrom-Json
    return $JSONObj
}

function Set-LocalStorageJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $JSONObj
    )
    
    $JSONObj | ConvertTo-Json -Depth 5 | Out-File $StorageFile
}

function Reset-TestStorage {
    Set-Content $TestStorageFile -Value (Get-Content (Join-Path -Path $PSScriptRoot -ChildPath ".\LocalStorage.json"))
}

function Set-ValueLocalStorageJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Key,
        [ValidateNotNullOrEmpty()]
        $Subkey,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Value
    )

    $JSONObj = Get-LocalStorageJSON
    if ($Subkey) {
        $JSONObj.$Key.$Subkey = $Value
    } else {
        $JSONObj.$Key = $Value
    }

    try {
        Set-LocalStorageJSON -JSONObj $JSONObj -ErrorAction Stop
    } catch {
        throw "Unable to set JSON value $Value within key $Key."
    }
}
