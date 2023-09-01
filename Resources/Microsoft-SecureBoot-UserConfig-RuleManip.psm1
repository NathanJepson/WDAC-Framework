function CountMapToPattern {
    [CmdletBinding()]
    param (
        $RuleMap,
        $Pattern
    )

    $Count = 0
    foreach ($Entry in $RuleMap.GetEnumerator()) {
        if ($Entry.Name -match $Pattern) {
            $Count += 1
        }
    }

    return $Count
}

function IncrementAllowID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_ALLOW_[A-Z][_A-F0-9]*") -le 0) {
        return "ID_ALLOW_A_A0"
    }

    $Max = -1
    foreach ($Entry in $RuleMap.GetEnumerator()) {
        #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
        if ($Entry.Name -match "ID_ALLOW_[A-Z][_A-F0-9]*") {
            $Split = ($Entry.Name) -split "_"
            $Hex = "0x$($Split[3])"
            $nextInt = [int]$Hex
            if ($nextInt -gt $Max) {
                $Max = $nextInt
            }
        }
    }

    $Max += 1
    #Convert Integer to Hex
    $EndPart = $Max.ToString("X") 
    $result = ("ID_ALLOW_A_" + $EndPart)
    while ($RuleMap[$result]) {
        $Max += 1
        $EndPart = $Max.ToString("X") 
        $result = ("ID_ALLOW_A_" + $EndPart)
    }

    return $result
}

function IncrementDenyID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_DENY_[A-Z][_A-F0-9]*") -le 0) {
        return "ID_DENY_D_A0"
    }

    $Max = -1
    foreach ($Entry in $RuleMap.GetEnumerator()) {
        #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
        if ($Entry.Name -match "ID_DENY_[A-Z][_A-F0-9]*") {
            $Split = ($Entry.Name) -split "_"
            $Hex = "0x$($Split[3])"
            $nextInt = [int]$Hex
            if ($nextInt -gt $Max) {
                $Max = $nextInt
            }
        }
    }

    $Max += 1
    #Convert Integer to Hex
    $EndPart = $Max.ToString("X") 
    $result = ("ID_DENY_D_" + $EndPart)
    while ($RuleMap[$result]) {
        $Max += 1
        $EndPart = $Max.ToString("X") 
        $result = ("ID_DENY_D_" + $EndPart)
    }

    return $result
}

function IncrementSignerID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_SIGNER_[A-Z][_A-F0-9]*") -le 0) {
        return "ID_SIGNER_S_A0"
    }

    $Max = -1
    foreach ($Entry in $RuleMap.GetEnumerator()) {
        #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
        if ($Entry.Name -match "ID_SIGNER_[A-Z][_A-F0-9]*") {
            $Split = ($Entry.Name) -split "_"
            $Hex = "0x$($Split[3])"
            $nextInt = [int]$Hex
            if ($nextInt -gt $Max) {
                $Max = $nextInt
            }
        }
    }

    $Max += 1
    #Convert Integer to Hex
    $EndPart = $Max.ToString("X") 
    $result = ("ID_SIGNER_S_" + $EndPart)
    while ($RuleMap[$result]) {
        $Max += 1
        $EndPart = $Max.ToString("X") 
        $result = ("ID_SIGNER_S_" + $EndPart)
    }

    return $result
}

function IncrementFileAttribID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_FILEATTRIB_[A-Z][_A-F0-9]*") -le 0) {
        return "ID_FILEATTRIB_F_A0"
    }

    $Max = -1
    foreach ($Entry in $RuleMap.GetEnumerator()) {
        #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
        if ($Entry.Name -match "ID_FILEATTRIB_[A-Z][_A-F0-9]*") {
            $Split = ($Entry.Name) -split "_"
            $Hex = "0x$($Split[3])"
            $nextInt = [int]$Hex
            if ($nextInt -gt $Max) {
                $Max = $nextInt
            }
        }
    }

    $Max += 1
    #Convert Integer to Hex
    $EndPart = $Max.ToString("X") 
    $result = ("ID_FILEATTRIB_F_" + $EndPart)
    while ($RuleMap[$result]) {
        $Max += 1
        $EndPart = $Max.ToString("X") 
        $result = ("ID_FILEATTRIB_F_" + $EndPart)
    }

    return $result
}

function New-MicrosoftSecureBootHashRule {
    [CmdletBinding()]
    param (
        [switch]$MSIorScript,
        $RuleInfo,
        $RuleMap
    )

    $result = @()
    $Name = (($RuleInfo.FirstDetectedPath + "\" + $RuleInfo.FileName) + " " + "Hash Sha256")
    #Name = ($RuleInfo.FirstDetectedPath + "\" + $RuleInfo.FileName)

    #The authenticode hash is used for hash rules involving PEs
    if ($MSIorScript) {
        $Hash = $RuleInfo.SHA256FlatHash
        #$SIPHash = $null #TODO
        return; #TODO
    } else {
        $Hash = $RuleInfo.SHA256AuthenticodeHash
    }

    $TemporaryFile = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $Name

    if ($RuleInfo.Blocked -eq $true) {
        $blockResultUserMode = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash",[Microsoft.SecureBoot.UserConfig.RuleType]"Deny",[Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
        $blockResultKernel = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash",[Microsoft.SecureBoot.UserConfig.RuleType]"Deny",[Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
        $ID_User = IncrementDenyID -RuleMap $RuleMap
        $RuleMap.Add($ID_User,$true)
        $ID_Kernel = IncrementDenyID -RuleMap $RuleMap
        if ($null -ne $RuleInfo.Comment -and "" -ne $RuleInfo.Comment) {
            $RuleMap[$ID_User] = $RuleInfo.Comment
            $RuleMap.Add($ID_Kernel,$RuleInfo.Comment)
        } else {
            $RuleMap.Add($ID_Kernel,$true)
        }
        $blockResultUserMode.Id = $ID_User
        $blockResultKernel.Id = $ID_Kernel
        # $blockResultUserMode.TypeId = "Deny"
        # $blockResultKernel.TypeId = "Deny"
        $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$Hash);
        $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$Hash);
        # $blockResultUserMode.Name = $Name
        # $blockResultKernel.Name = $Name
        $result += $blockResultUserMode
        $result += $blockResultKernel

    } else {
        #NOTE: If both TrustedDriver and TrustedUserMode are marked, there is a condition which handles this outside the function, so don't worry about that
        if ($RuleInfo.TrustedDriver -eq $true) {
            $kernelResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash",[Microsoft.SecureBoot.UserConfig.RuleType]"Allow",[Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
            $ID_Kernel = IncrementAllowID -RuleMap $RuleMap
            if ($null -ne $RuleInfo.Comment -and "" -ne $RuleInfo.Comment) {
                $RuleMap.Add($ID_Kernel,$RuleInfo.Comment)
            } else {
                $RuleMap.Add($ID_Kernel,$true)
            }
            $kernelResult.ID = $ID_Kernel
            # $kernelResult.TypeId = "Allow"
            $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$Hash);
            # $kernelResult.Name = $Name
            $result += $kernelResult
        }
        if ($RuleInfo.TrustedUserMode -eq $true) {
            $userModeResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash",[Microsoft.SecureBoot.UserConfig.RuleType]"Allow",[Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
            $ID_User = IncrementAllowID -RuleMap $RuleMap
            if ($null -ne $RuleInfo.Comment -and "" -ne $RuleInfo.Comment) {
                $RuleMap.Add($ID_User,$RuleInfo.Comment)
            } else {
                $RuleMap.Add($ID_User,$true)
            }
            $userModeResult.ID = $ID_User
            # $userModeResult.TypeId = "Allow"
            $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$Hash);
            # $userModeResult.Name = $Name
            $result += $userModeResult
        }
    }

    #$result | Out-Host #FIXME
    return $result,$RuleMap
}
function New-MicrosoftSecureBootFilePathRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )

    #TODO: FilePath rules not yet implemented
}

function New-MicrosoftSecureBootFileNameRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootLeafCertificateRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootPcaCertificateRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootPublisherRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}

function New-MicrosoftSecureBootFilePublisherRule {
    [CmdletBinding()]
    param (
        $RuleInfo
    )
}


Export-ModuleMember -Function New-MicrosoftSecureBootHashRule