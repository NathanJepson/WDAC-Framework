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

function Get-WDACWorkstationProcessorArchitecture {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
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
        $Command.Commandtext = "Select processor_architecture from devices WHERE DeviceName = @DeviceName"
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $Reader["processor_architecture"]
            }
        }
        $Reader.Close()
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

function Add-WDACWorkstationProcessorArchitecture {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$ProcessorArchitecture,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE devices SET processor_architecture = @processor_architecture WHERE DeviceName = @DeviceName"
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.Parameters.AddWithValue("processor_architecture",$ProcessorArchitecture) | Out-Null
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

function Get-WDACDevicesByGroupToPolicyMapping {
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
                    DeviceName = $Reader["DeviceName"];
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

function Get-WDACDevicesByMirroredGroupToPolicyMapping {
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
                    DeviceName = $Reader["DeviceName"];
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

function Get-WDACDevicesByAdHocPolicyMapping {
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
                    DeviceName = $Reader["DeviceName"];
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

function Get-WDACDevicesNeedingWDACPolicy {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Deferred,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $DeviceMap = @{}

        $DeviceList1 = Get-WDACDevicesByGroupToPolicyMapping -PolicyGUID $PolicyGUID -Deferred:$Deferred -Connection $Connection 
        $DeviceList2 = Get-WDACDevicesByMirroredGroupToPolicyMapping -PolicyGUID $PolicyGUID -Deferred:$Deferred -Connection $Connection
        $DeviceList3 = Get-WDACDevicesByAdHocPolicyMapping -PolicyGUID $PolicyGUID -Deferred:$Deferred -Connection $Connection

        foreach ($Device in $DeviceList1) {
            if (-not ($DeviceMap.ContainsKey($Device.DeviceName))) {
                $DeviceMap += @{ ($Device.DeviceName) = $Device.processor_architecture}
            }
        }
        foreach ($Device in $DeviceList2) {
            if (-not ($DeviceMap.ContainsKey($Device.DeviceName))) {
                $DeviceMap += @{ ($Device.DeviceName) = $Device.processor_architecture}
            }
        }
        foreach ($Device in $DeviceList3) {
            if (-not ($DeviceMap.ContainsKey($Device.DeviceName))) {
                $DeviceMap += @{ ($Device.DeviceName) = $Device.processor_architecture}
            }
        }

        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $DeviceMap
    } catch {
        $theError = $_
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        throw $theError
    }
}

function Get-WDACDevicesAllNamesAndCPUInfo {
    [cmdletbinding()]
    Param ( 
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

        if ($Deferred) {
            $Command.Commandtext = "SELECT DeviceName,processor_architecture from Devices WHERE UpdateDeferring = 1"
        } else {
            $Command.Commandtext = "SELECT DeviceName,processor_architecture from Devices WHERE UpdateDeferring = 0"
        }
        
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if (-not $result) {
                $result = @()
            }
            if($Reader.Read()) {
                $result += (Format-SQLResult ([PSCustomObject]@{
                    DeviceName = $Reader["DeviceName"];
                    processor_architecture = $Reader["processor_architecture"]
                }))
            }
        }

        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        
        $DeviceMap = @{}
        foreach ($Device in $result) {
            if (-not ($DeviceMap[($Device.DeviceName)])) {
                $DeviceMap += @{ ($Device.DeviceName) = $Device.processor_architecture}
            }
        }

        return $DeviceMap
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

function Test-DeferredWDACPolicy {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeferredDevicePolicyGUID,
        $PolicyVersion=$null,
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

        if (-not $PolicyVersion) {
            $Command.Commandtext = "SELECT * from deferred_policies WHERE DeferredDevicePolicyGUID = @DeferredDevicePolicyGUID AND PolicyVersion is NULL"
        } else {
            $Command.Commandtext = "SELECT * from deferred_policies WHERE DeferredDevicePolicyGUID = @DeferredDevicePolicyGUID AND PolicyVersion = @PolicyVersion"
        }
        $Command.Parameters.AddWithValue("DeferredDevicePolicyGUID",$DeferredDevicePolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("PolicyVersion",$PolicyVersion) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Get-DeferredWDACPolicy {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeferredDevicePolicyGUID,     
        $PolicyVersion=$null,
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

        if ($PolicyVersion) {
            $Command.Commandtext = "SELECT * from deferred_policies WHERE DeferredDevicePolicyGUID = @DeferredDevicePolicyGUID AND PolicyVersion = @PolicyVersion"
            $Command.Parameters.AddWithValue("PolicyVersion",$PolicyVersion) | Out-Null
        } else {
            $Command.Commandtext = "SELECT * from deferred_policies WHERE DeferredDevicePolicyGUID = @DeferredDevicePolicyGUID AND PolicyVersion is NULL"
        }
        $Command.Parameters.AddWithValue("DeferredDevicePolicyGUID",$DeferredDevicePolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [PSCustomObject]@{
                    DeferredPolicyIndex = [int]$Reader["DeferredPolicyIndex"];
                    DeferredDevicePolicyGUID = $Reader["DeferredDevicePolicyGUID"];
                    PolicyVersion = $Reader["PolicyVersion"];
                    IsSigned = [bool]$Reader["IsSigned"]
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

function Get-DeferredWDACPolicies {
#The difference with Get-DeferredWDACPolicy is that this cmdlet gets ALL deferred policies for a given policy GUID
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeferredDevicePolicyGUID,
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
        $Command.Commandtext = "SELECT * from deferred_policies WHERE DeferredDevicePolicyGUID = @DeferredDevicePolicyGUID"
        $Command.Parameters.AddWithValue("DeferredDevicePolicyGUID",$DeferredDevicePolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                
                if (-not $result) {
                    $result = @()
                }

                $result += [PSCustomObject]@{
                    DeferredPolicyIndex = [int]$Reader["DeferredPolicyIndex"];
                    DeferredDevicePolicyGUID = $Reader["DeferredDevicePolicyGUID"];
                    PolicyVersion = $Reader["PolicyVersion"];
                    IsSigned = [bool]$Reader["IsSigned"]
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

function Get-WDACPolicyLatestDeployedSignedStatus {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        if (-not $PolicyInfo.LastDeployedPolicyVersion) {
            return $false
        }

        if ($PolicyInfo.LastSignedVersion -and $PolicyInfo.LastUnsignedVersion) {
            
            if ( (Compare-Versions -Version1 $PolicyInfo.LastUnsignedVersion -Version2 $PolicyInfo.LastDeployedPolicyVersion) -eq -1) {
            #LastUnsignedVersion < LastDeployedPolicyVersion
            #This means that the most recently deployed policy would have to have been signed
                return $true
            } elseif ((Compare-Versions -Version1 $PolicyInfo.LastSignedVersion -Version2 $PolicyInfo.LastDeployedPolicyVersion) -eq 0) {
            #If the last deployed version number is the same as the most recent signed version, then that means the most recently
            #...deployed version was signed
                return $true
            } elseif (((Compare-Versions -Version1 $PolicyInfo.LastUnsignedVersion -Version2 $PolicyInfo.LastDeployedPolicyVersion) -eq 1) -and ((Compare-Versions -Version1 $PolicyInfo.LastSignedVersion -Version2 $PolicyInfo.LastDeployedPolicyVersion) -eq 1)) {
            #If the last signed version and last unsigned version numbers > latest deployed policy version
                if ($PolicyInfo.DeployedSigned -eq $true) {
                    return $true
                } else {
                    return $false
                }
            } else {
                return $false
            }

        } elseif ($PolicyInfo.LastSignedVersion) {
            if (-not ($PolicyInfo.LastDeployedPolicyVersion)) {
                return $false
            } else {
            #If a policy is deployed, and there's only a LastSignedVersion, then the deployed policy was signed
                return $true
            }
        } elseif ($PolicyInfo.LastUnsignedVersion) {
            return $false
        } else {
            return $false
        }


        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        return $result

    } catch {
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        throw $_
    }
}

function Add-DeferredWDACPolicy {
#This function takes the current WDAC policy by the GUID and 
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $CurrentWDACPolicy = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        $DeferredVersion = $CurrentWDACPolicy.LastDeployedPolicyVersion

        if (Test-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $DeferredVersion -Connection $Connection -ErrorAction Stop) {
        #If there is already a deferred policy entry for this version of the policy, then return
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }
            return $true;
        }

        #Find out if the latest deployed version of the policy is signed or not-signed
        $DeferredSigned = Get-WDACPolicyLatestDeployedSignedStatus -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        $Command = $Connection.CreateCommand()
        if ($DeferredVersion) {
            $Command.Commandtext = "INSERT INTO deferred_policies (DeferredDevicePolicyGUID,PolicyVersion,IsSigned) values (@DeferredDevicePolicyGUID,@PolicyVersion,@IsSigned)"
            $Command.Parameters.AddWithValue("PolicyVersion",$DeferredVersion) | Out-Null
        } else {
            $Command.Commandtext = "INSERT INTO deferred_policies (DeferredDevicePolicyGUID,IsSigned) values (@DeferredDevicePolicyGUID,@IsSigned)"
        }
            
        $Command.Parameters.AddWithValue("DeferredDevicePolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("IsSigned",$DeferredSigned) | Out-Null
            
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

function Remove-DeferredWDACPolicy {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeferredPolicyIndex,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.CommandText = "PRAGMA foreign_keys=ON;"
            #This PRAGMA is needed so that foreign key constraints will work upon deleting
        $Command.Commandtext += "DELETE FROM deferred_policies WHERE DeferredPolicyIndex = @DeferredPolicyIndex"
        $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
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

function Test-PolicyDeferredOnDevice {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$WorkstationName,
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

        #Select * from deferred_policies_assignments as dpa inner join deferred_policies as dp on dp.DeferredPolicyIndex = dpa.DeferredPolicyIndex 
        #WHERE dp.DeferredDevicePolicyGUID = @PolicyGUID AND dpa.DeviceName = @WorkstationName

        $Command.Commandtext = "Select * from deferred_policies_assignments as dpa INNER JOIN deferred_policies as dp on dp.DeferredPolicyIndex = dpa.DeferredPolicyIndex WHERE dp.DeferredDevicePolicyGUID = @PolicyGUID AND dpa.DeviceName = @WorkstationName"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("WorkstationName",$WorkstationName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Test-SpecificDeferredPolicyOnDevice {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$DeferredPolicyIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$WorkstationName,
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

        $Command.Commandtext = "Select * from deferred_policies_assignments WHERE DeviceName = @WorkstationName AND DeferredPolicyIndex = @DeferredPolicyIndex"
        $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
        $Command.Parameters.AddWithValue("WorkstationName",$WorkstationName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Get-WDACWorkstationsByDeferredPolicyIndex {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Index","PolicyIndex")]
        [string]$DeferredPolicyIndex,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = @()
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        
        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "Select devices.DeviceName from devices inner join deferred_policies_assignments on deferred_policies_assignments.DeviceName = devices.DeviceName WHERE DeferredPolicyIndex = @DeferredPolicyIndex;"
        $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result += $Reader["DeviceName"];
            }
        }
        if ($Reader) {
            $Reader.Close()
        }
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }

        if ($result.Count -eq 0) {
            return $null
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

function Add-DeferredWDACPolicyAssignment {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeferredPolicyIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        $Comment,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        if ($Comment) {
            $Command.Commandtext = "INSERT INTO deferred_policies_assignments (DeferredPolicyIndex,DeviceName,Comment) values (@DeferredPolicyIndex,@DeviceName,@Comment)"
            $Command.Parameters.AddWithValue("Comment",$Comment) | Out-Null
        } else {
            $Command.Commandtext = "INSERT INTO deferred_policies_assignments (DeferredPolicyIndex,DeviceName) values (@DeferredPolicyIndex,@DeviceName)"
        }
        $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
            
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

function Remove-DeferredWDACPolicyAssignment {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeferredPolicyIndex,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.CommandText = "PRAGMA foreign_keys=ON;"
            #This PRAGMA is needed so that foreign key constraints will work upon deleting
        $Command.Commandtext += "DELETE FROM deferred_policies_assignments WHERE DeferredPolicyIndex = @DeferredPolicyIndex AND DeviceName = @DeviceName"
        $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
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

function Test-AnyDeferredWDACPolicyAssignments {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [int]$DeferredPolicyIndex,
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

        $Command.Commandtext = "Select * from deferred_policies_assignments WHERE DeferredPolicyIndex = @DeferredPolicyIndex"
        $Command.Parameters.AddWithValue("DeferredPolicyIndex",$DeferredPolicyIndex) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Test-WDACPolicyDeferred {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("DeferredDevicePolicyGUID")]
        [string]$PolicyGUID,
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

        $Command.Commandtext = "Select * from deferred_policies WHERE DeferredDevicePolicyGUID = @DeferredDevicePolicyGUID"
        $Command.Parameters.AddWithValue("DeferredDevicePolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Test-AnyPoliciesDeferredOnDevice {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$WorkstationName,
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

        $Command.Commandtext = "Select * from deferred_policies_assignments where DeviceName = @WorkstationName"
        $Command.Parameters.AddWithValue("WorkstationName",$WorkstationName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Get-WDACPolicyLastUnsignedVersion {
    [cmdletbinding()]
    Param (
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
        $Command.Commandtext = "Select LastUnsignedVersion from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
        
            if($Reader.Read()) {
                $result = $Reader["LastUnsignedVersion"]
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($result -is [System.DBNull]) {
            return $null
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

function Get-WDACPolicyLastSignedVersion {
    [cmdletbinding()]
    Param (
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
        $Command.Commandtext = "Select LastSignedVersion from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {

            if($Reader.Read()) {
                $result = $Reader["LastSignedVersion"]
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($result -is [System.DBNull]) {
            return $null
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

function Get-WDACPolicyLastDeployedVersion {
    [cmdletbinding()]
    Param (
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
        $Command.Commandtext = "Select LastDeployedPolicyVersion from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            
            if($Reader.Read()) {
                $result = $Reader["LastDeployedPolicyVersion"]
            }
        }
        $Reader.Close()
        if ($NoConnectionProvided -and $Connection) {
            $Connection.close()
        }
        if ($result -is [System.DBNull]) {
            return $null
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

function Set-WDACPolicyLastDeployedVersion {
#This function sets the LastDeployedPolicyVersion to be the same as the current version of the policy
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

        $CurrentVersion = Get-WDACPolicyVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        if (-not $CurrentVersion) {
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }
            throw "Policy $PolicyGUID currently doesn't have a valid policy version number."
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE policies SET LastDeployedPolicyVersion = @CurrentVersion WHERE PolicyGUID = @PolicyGUID"        
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("CurrentVersion",$CurrentVersion) | Out-Null
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

function Set-WDACPolicyLastSignedVersion {
    #This function sets the LastDeployedPolicyVersion to be the same as the current version of the policy
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        $PolicyVersion,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        if (-not $PolicyVersion) {
            $PolicyVersion = Get-WDACPolicyVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        }
        if (-not $PolicyVersion) {
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }
            throw "Policy $PolicyGUID currently doesn't have a valid policy version number."
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "UPDATE policies SET LastSignedVersion = @CurrentVersion WHERE PolicyGUID = @PolicyGUID"        
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("CurrentVersion",$PolicyVersion) | Out-Null
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

function Set-WDACPolicyLastUnsignedVersion {
     #This function sets the LastDeployedPolicyVersion to be the same as the current version of the policy
     [cmdletbinding()]
     Param (
         [ValidateNotNullOrEmpty()]
         [Parameter(Mandatory=$true)]
         [string]$PolicyGUID,
         $PolicyVersion,
         [System.Data.SQLite.SQLiteConnection]$Connection
     )
 
     try {
         if (-not $Connection) {
             $Connection = New-SQLiteConnection -ErrorAction Stop
             $NoConnectionProvided = $true
         }
 
         if (-not $PolicyVersion) {
             $PolicyVersion = Get-WDACPolicyVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
         }
         if (-not $PolicyVersion) {
             if ($NoConnectionProvided -and $Connection) {
                 $Connection.close()
             }
             throw "Policy $PolicyGUID currently doesn't have a valid policy version number."
         }
 
         $Command = $Connection.CreateCommand()
         $Command.Commandtext = "UPDATE policies SET LastUnsignedVersion = @CurrentVersion WHERE PolicyGUID = @PolicyGUID"        
         $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
         $Command.Parameters.AddWithValue("CurrentVersion",$PolicyVersion) | Out-Null
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

function Test-MustRemoveSignedPolicy {
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

        if (Test-WDACPolicySigned -PolicyGuid $PolicyGUID -Connection $Connection -ErrorAction Stop) {
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }

            return $false
        
        } else {
            $LastUnsignedVersion = Get-WDACPolicyLastUnsignedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            $LastSignedVersion = Get-WDACPolicyLastSignedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            $LastDeployedPolicyVersion = Get-WDACPolicyLastDeployedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

            if (-not $LastDeployedPolicyVersion) {
            #Policy was never deployed
                return $false
            }

            if ( (Compare-Versions -Version1 $LastUnsignedVersion -Version2 $LastSignedVersion) -eq 1) {
            #If the more recent version is unsigned

                if (Get-WDACPolicyLatestDeployedSignedStatus -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) {
                #Last deployed policy was actually signed
                    
                    return $true
                } else {
                    return $false
                }
            } else {
            #Case LastUnsignedVersion < LastSignedVersion

                return $false
            }
    
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }
            
            return $result
        }

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

function Test-FirstSignedPolicyDeployment {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
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

        $Command.Commandtext = "Select * from first_signed_policy_deployments where DeviceName = @DeviceName AND PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Get-DeployedSignedPolicyStatus {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
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
        $Command.Commandtext = "Select DeployedSigned from policies WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null
        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = [bool]$Reader["DeployedSigned"]
            }
        }
        $Reader.Close()
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

function Set-ToggledDeployedSignedStatus {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [switch]$Remove,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        if ($Remove) {
            $Command.Commandtext = "UPDATE policies SET DeployedSigned = 0 WHERE PolicyGUID = @PolicyGUID"
        } else {
            $Command.Commandtext = "UPDATE policies SET DeployedSigned = 1 WHERE PolicyGUID = @PolicyGUID"
        }
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

function Add-FirstSignedPolicyDeployment {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false
    
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        if (-not (Get-DeployedSignedPolicyStatus -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
            if (-not (Set-ToggledDeployedSignedStatus -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                throw "Unable to set DeployedSigned flag for policy $PolicyGUID"
            }
        }

        $Command = $Connection.CreateCommand()
        $Command.Commandtext = "INSERT INTO first_signed_policy_deployments (PolicyGUID,DeviceName) values (@PolicyGUID,@DeviceName)"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
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

function Remove-FirstSignedPolicyDeployment {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [string]$DeviceName,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    
    if (-not (Test-FirstSignedPolicyDeployment -PolicyGUID $PolicyGUID -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop)) {
        return $true
    }

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        $Command = $Connection.CreateCommand()
        $Command.CommandText = "PRAGMA foreign_keys=ON;"
            #This PRAGMA is needed so that foreign key constraints will work upon deleting
        $Command.Commandtext += "DELETE FROM first_signed_policy_deployments WHERE PolicyGUID = @PolicyGUID AND DeviceName = @DeviceName"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
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

function Remove-AllFirstSignedPolicyDeployments {
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    
    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        if (Get-DeployedSignedPolicyStatus -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) {
            if (-not (Set-ToggledDeployedSignedStatus -PolicyGUID $PolicyGUID -Remove -Connection $Connection -ErrorAction Stop)) {
                throw "Unable to unset DeployedSigned flag for policy $PolicyGUID"
            }
        }

        $Command = $Connection.CreateCommand()
        $Command.CommandText = "PRAGMA foreign_keys=ON;"
            #This PRAGMA is needed so that foreign key constraints will work upon deleting
        $Command.Commandtext += "DELETE FROM first_signed_policy_deployments WHERE PolicyGUID = @PolicyGUID"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
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

function Remove-FirstSignedPolicyDeploymentsConditional {
#If a policy is deployed unsigned, and some devices are no longer deferred on that policy, then remove the first_signed_policy_deployments for those
#devices on that policy
    [cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$PolicyGUID,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $NoConnectionProvided = $false

    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }
        $Command = $Connection.CreateCommand()
        $Command.CommandText = "PRAGMA foreign_keys=ON;"
            #This PRAGMA is needed so that foreign key constraints will work upon deleting
        $Command.CommandText += "DELETE from first_signed_policy_deployments WHERE DeviceName in (Select fs.DeviceName from policies as po INNER JOIN first_signed_policy_deployments as fs on fs.PolicyGUID = po.PolicyGUID WHERE po.LastDeployedPolicyVersion = po.LastUnsignedVersion AND po.PolicyGUID = @PolicyGUID AND fs.DeviceName NOT IN (SELECT dpa.DeviceName from deferred_policies_assignments as dpa INNER JOIN deferred_policies as dp on dp.DeferredPolicyIndex = dpa.DeferredPolicyIndex WHERE dp.DeferredDevicePolicyGUID = @PolicyGUID));"
        $Command.Parameters.AddWithValue("PolicyGUID",$PolicyGUID) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
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

function Test-WDACDeviceDeferred {
    [cmdletbinding()]
    Param ( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,
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

        $Command.Commandtext = "Select * from devices where DeviceName = @DeviceName AND UpdateDeferring = 1"
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
        $Command.CommandType = [System.Data.CommandType]::Text
        $Reader = $Command.ExecuteReader()
        $Reader.GetValues() | Out-Null

        while($Reader.HasRows) {
            if($Reader.Read()) {
                $result = $true
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

function Set-WDACDeviceDeferredStatus {
    [cmdletbinding()]
    Param ( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,
        [switch]$Unset,
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    
    try {
        if (-not $Connection) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $NoConnectionProvided = $true
        }

        if ((-not $Unset) -and (Test-WDACDeviceDeferred -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop)) {
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }
            return $true
        } elseif ($Unset -and (-not (Test-WDACDeviceDeferred -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop))) {
            if ($NoConnectionProvided -and $Connection) {
                $Connection.close()
            }    
            return $true
        }

        $Command = $Connection.CreateCommand()
        if ($Unset) {
            $Command.Commandtext = "UPDATE devices SET UpdateDeferring = 0 WHERE DeviceName = @DeviceName"
        } else {
            $Command.Commandtext = "UPDATE devices SET UpdateDeferring = 1 WHERE DeviceName = @DeviceName"
        }
        $Command.Parameters.AddWithValue("DeviceName",$DeviceName) | Out-Null
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