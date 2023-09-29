if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

function Get-DevicesByGroupToPolicyMapping {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Deferred,
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

        # Select DeviceName,processor_architecture from devices AS dev
        # INNER JOIN  
        # groups as gro
        # ON gro.GroupName = dev.AllowedGroup
        # INNER JOIN
        # policy_assignments as pa
        # ON gro.GroupName = pa.GroupName
        # WHERE pa.PolicyGUID = @PolicyGUID
        # AND dev.UpdateDeferring = 0
        
        if ($Deferred) {
            $Command.Commandtext = "Select DeviceName,processor_architecture from devices AS dev INNER JOIN groups as gro ON gro.GroupName = dev.AllowedGroup INNER JOIN policy_assignments as pa ON gro.GroupName = pa.GroupName WHERE pa.PolicyGUID = @PolicyGUID AND dev.UpdateDeferring = 1"
        } else {
            $Command.Commandtext = "Select DeviceName,processor_architecture from devices AS dev INNER JOIN groups as gro ON gro.GroupName = dev.AllowedGroup INNER JOIN policy_assignments as pa ON gro.GroupName = pa.GroupName WHERE pa.PolicyGUID = @PolicyGUID AND dev.UpdateDeferring = 0"
        }
        
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    DeviceName = $Reader["DeviceName"]
                    processor_architecture = $Reader["processor_architecture"]
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

function Get-DevicesByMirroredGroupToPolicyMapping {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Deferred,
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

        # Select DeviceName,processor_architecture from devices AS dev
        # INNER JOIN  
        # groups as gro
        # ON gro.GroupName = dev.AllowedGroup
        # INNER JOIN 
        # group_mirrors as gm
        # ON gm.GroupName = gro.GroupName
        # INNER JOIN
        # policy_assignments as pa
        # ON gm.MirroredGroupName = pa.GroupName
        # WHERE pa.PolicyGUID = @PolicyGUID
        # AND dev.UpdateDeferring = 0
        
        if ($Deferred) {
            $Command.Commandtext = "Select DeviceName,processor_architecture from devices AS dev INNER JOIN groups as gro ON gro.GroupName = dev.AllowedGroup INNER JOIN group_mirrors as gm ON gm.GroupName = gro.GroupName INNER JOIN policy_assignments as pa ON gm.MirroredGroupName = pa.GroupName WHERE pa.PolicyGUID = @PolicyGUID AND dev.UpdateDeferring = 1"
        } else {
            $Command.Commandtext = "Select DeviceName,processor_architecture from devices AS dev INNER JOIN groups as gro ON gro.GroupName = dev.AllowedGroup INNER JOIN group_mirrors as gm ON gm.GroupName = gro.GroupName INNER JOIN policy_assignments as pa ON gm.MirroredGroupName = pa.GroupName WHERE pa.PolicyGUID = @PolicyGUID AND dev.UpdateDeferring = 0"
        }
        
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    DeviceName = $Reader["DeviceName"]
                    processor_architecture = $Reader["processor_architecture"]
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

function Get-DevicesByAdHocPolicyMapping {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Deferred,
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

        # SELECT DeviceName,processor_architecture from Devices as dev
        # INNER JOIN
        # ad_hoc_policy_assignments as ah
        # ON ah.DeviceName = dev.DeviceName
        # WHERE ah.PolicyGUID = @PolicyGUID
        # AND dev.UpdateDeferring = 0

        if ($Deferred) {
            $Command.Commandtext = "SELECT dev.DeviceName,dev.processor_architecture from Devices as dev INNER JOIN ad_hoc_policy_assignments as ah ON ah.DeviceName = dev.DeviceName WHERE ah.PolicyGUID = @PolicyGUID AND dev.UpdateDeferring = 1"
        } else {
            $Command.Commandtext = "SELECT dev.DeviceName,dev.processor_architecture from Devices as dev INNER JOIN ad_hoc_policy_assignments as ah ON ah.DeviceName = dev.DeviceName WHERE ah.PolicyGUID = @PolicyGUID AND dev.UpdateDeferring = 0"
        }
        
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += [PSCustomObject]@{
                    DeviceName = $Reader["DeviceName"]
                    processor_architecture = $Reader["processor_architecture"]
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

function Get-DevicesNeedingWDACPolicy {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )


    #TODO
    
	
}
