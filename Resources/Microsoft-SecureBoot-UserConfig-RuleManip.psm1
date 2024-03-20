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

    try {
        if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_ALLOW_[A-Z][_A-F0-9]*") -le 0) {
            return "ID_ALLOW_A_A0"
        }
    
        $Max = -1
        foreach ($Entry in $RuleMap.GetEnumerator()) {
            #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
            if ($Entry.Name -match "ID_ALLOW_[A-Z][_A-F0-9]+$") {
                $Split = ($Entry.Name) -split "_"
                $Hex = "0x$($Split[-1])"
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

    } catch {
        Write-Warning "Error in IncrementAllowID function."
        throw $_
    }
}

function IncrementDenyID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    try {
        if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_DENY_[A-Z][_A-F0-9]*") -le 0) {
            return "ID_DENY_D_A0"
        }
    
        $Max = -1
        foreach ($Entry in $RuleMap.GetEnumerator()) {
            #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
            if ($Entry.Name -match "ID_DENY_[A-Z][_A-F0-9]+$") {
                $Split = ($Entry.Name) -split "_"
                $Hex = "0x$($Split[-1])"
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
    } catch {
        Write-Warning "Error in IncrementDenyID function."
        throw $_
    }
}

function IncrementSignerID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    try {
        if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_SIGNER_[A-Z][_A-F0-9]*") -le 0) {
            return "ID_SIGNER_S_A0"
        }
    
        $Max = -1
        foreach ($Entry in $RuleMap.GetEnumerator()) {
            #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
            if ($Entry.Name -match "ID_SIGNER_[A-Z][_A-F0-9]+$") {
                $Split = ($Entry.Name) -split "_"
                $Hex = "0x$($Split[-1])"
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
    } catch {
        Write-Warning "Error in IncrementSignerID function."
        throw $_
    }
    
}

function IncrementFileAttribID {
    [CmdletBinding()]
    param (
        $RuleMap
    )

    try {
        if ((-not $RuleMap) -or (CountMapToPattern -RuleMap $RuleMap -Pattern "ID_FILEATTRIB_[A-Z][_A-F0-9]*") -le 0) {
            return "ID_FILEATTRIB_F_A0"
        }
    
        $Max = -1
        foreach ($Entry in $RuleMap.GetEnumerator()) {
            #Here we specify [_A-F0-9] as the final part of the ID even though [_A-Z0-9] is permitted as an id. This is because hexadecimal is easier to work with.
            if ($Entry.Name -match "ID_FILEATTRIB_[A-Z][_A-F0-9]+$") {
                $Split = ($Entry.Name) -split "_"
                $Hex = "0x$($Split[-1])"
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
    } catch {
        Write-Warning "Error in IncrementFileAttribID function."
        throw $_
    }
}

function New-MicrosoftSecureBootHashRule {
    [CmdletBinding()]
    param (
        [switch]$MSIorScript,
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap
    )

    $result = @()
    if (-not $MSIorScript) {
        $Name = ([string](($RuleInfo.FirstDetectedPath)+"\"+($RuleInfo.FileName)))
    } else {
        $Name = $RuleInfo.FirstDetectedPath
    }

    #Replace the Letter-name drive, otherwise an error occurs when creating the DriverFile object shell: Exception calling ".ctor" with "1" argument(s): "Operation is not supported on this platform. (0x80131539)"
    if ((Split-Path $Name -Qualifier) -match "^[A-Z]\:") {
        $Name = $Name.Substring(2)
        $Name = "%OSDRIVE%" + $Name
    }

    #The authenticode hash is used for hash rules involving PEs.
    #When blocking MSIs and Scripts, the SIP hash is also used (further down)
    if ($MSIorScript) {
        $Hash = $RuleInfo.SHA256FlatHash
    } else {
        $Hash = $RuleInfo.SHA256AuthenticodeHash
    }

    $TemporaryFile = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $Name

    if ($RuleInfo.Blocked -eq $true) {
        #I'm not sure why, but I have to specify a FileName level even though it's just a hash rule
        $blockResultUserMode = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash", [Microsoft.SecureBoot.UserConfig.RuleType]"Deny", "Sha256", [Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
        $blockResultKernel = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash", [Microsoft.SecureBoot.UserConfig.RuleType]"Deny", "Sha256", [Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
        $ID_User = IncrementDenyID -RuleMap $RuleMap
        $RuleMap = $RuleMap + @{$ID_User=$true}
        $ID_Kernel = IncrementDenyID -RuleMap $RuleMap
        if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
            $RuleMap[$ID_User] = $RuleInfo.Comment
            $RuleMap = $RuleMap + @{$ID_Kernel=$RuleInfo.Comment}
        } elseif (-not ($MSIorScript)) {
            $FlatHashComment = "SHA256 Flat Hash: $($RuleInfo.SHA256FlatHash)"
            $RuleMap[$ID_User] = $FlatHashComment
            $RuleMap = $RuleMap + @{$ID_Kernel=$FlatHashComment}
        } else {
            $RuleMap = $RuleMap + @{$ID_Kernel=$true}
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
        if (-not $MSIorScript) {
            $result += $blockResultKernel
        }
        
        if ($RuleInfo.SHA256SipHash -and $MSIorScript) {
        #Note, SIP hashes are often used when blocking MSIs or Scripts
            $SIPHash = $RuleInfo.SHA256SipHash
            $blockResultSIP = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash", [Microsoft.SecureBoot.UserConfig.RuleType]"Deny", "Authenticode SIP Sha256", [Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
            $ID_User_SIP = IncrementDenyID -RuleMap $RuleMap
            $RuleMap = $RuleMap + @{$ID_User_SIP=$true}
            if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
                $RuleMap[$ID_User_SIP] = $RuleInfo.Comment
            } else {
                $FlatHashComment = "SHA256 Flat Hash: $($RuleInfo.SHA256FlatHash)"
                $RuleMap[$ID_User_SIP] = $FlatHashComment
            }

            $blockResultSIP.Id = $ID_User_SIP
            $blockResultSIP.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$SIPHash);
            $result += $blockResultSIP
        }
    } else {
        if ($RuleInfo.TrustedDriver -eq $true) {
            $kernelResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash", [Microsoft.SecureBoot.UserConfig.RuleType]"Allow", "Sha256", [Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
            $ID_Kernel = IncrementAllowID -RuleMap $RuleMap
            if ($null -ne $RuleInfo.Comment -and "" -ne $RuleInfo.Comment) {
                $RuleMap = $RuleMap + @{$ID_Kernel=$RuleInfo.Comment}
            } elseif (-not ($MSIorScript)) {
                $RuleMap = $RuleMap + @{$ID_Kernel=("SHA256 Flat Hash: $($RuleInfo.SHA256FlatHash)")}
            } else {
                $RuleMap = $RuleMap + @{$ID_Kernel=$true}
            }
            $kernelResult.ID = $ID_Kernel
            # $kernelResult.TypeId = "Allow"
            $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$Hash);
            # $kernelResult.Name = $Name
            $result += $kernelResult
        }
        if ($RuleInfo.TrustedUserMode -eq $true) {
            $userModeResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"Hash", [Microsoft.SecureBoot.UserConfig.RuleType]"Allow", "Sha256", [Microsoft.SecureBoot.UserConfig.FileNameLevel]"OriginalFileName")
            $ID_User = IncrementAllowID -RuleMap $RuleMap
            if ($null -ne $RuleInfo.Comment -and "" -ne $RuleInfo.Comment) {
                $RuleMap = $RuleMap + @{$ID_User=$RuleInfo.Comment}
            } elseif (-not ($MSIorScript)) {
                $RuleMap = $RuleMap + @{$ID_User=("SHA256 Flat Hash: $($RuleInfo.SHA256FlatHash)")}
            } else {
                $RuleMap = $RuleMap + @{$ID_User=$true}
            }
            $userModeResult.ID = $ID_User
            # $userModeResult.TypeId = "Allow"
            $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"Hash",$Hash);
            # $userModeResult.Name = $Name
            $result += $userModeResult
        }
    }

    return $result,$RuleMap
}

function Remove-UnderscoreDigits {
    #This function removes the underscore digits at the end ONLY IF we've already accounted for duplicates -- should ONLY be used when duplicates are accounted for
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $FilePath
        )
    
        $Pattern1 = '(?<=")ID_ALLOW_[A-Z][_A-Z0-9]+(?=")'
        $Pattern2 = '(?<=")ID_DENY_[A-Z][_A-Z0-9]+(?=")'
        $Pattern3 = '(?<=")ID_SIGNER_[A-Z][_A-Z0-9]+(?=")'
        $Pattern4 = '(?<=")ID_FILEATTRIB_[A-Z][_A-Z0-9]+(?=")'
        
        $FileContent = Get-Content -Path $FilePath -ErrorAction Stop
    
        for ($i=0; $i -lt $FileContent.Count; $i++) {
            if ( ($FileContent[$i] -match $Pattern1) -or ($FileContent[$i] -match $Pattern2) -or ($FileContent[$i] -match $Pattern3) -or ($FileContent[$i] -match $Pattern4)) {
                $FileContent[$i] = $FileContent[$i].replace($Matches[0],$Matches[0].Substring(0,$Matches[0].Length-2))
            }
        }
    
        $FileContent | Set-Content -Path $FilePath -Force -ErrorAction Stop
}

function New-MicrosoftSecureBootFilePathRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo
    )

    #TODO: FilePath rules not yet implemented
}

function New-MicrosoftSecureBootFileNameRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap
    )

    $result = @()
    $Name = $RuleInfo.FileName
    #For some reason, using an actual file name with extension results in this error: "Operation is not supported on this platform. (0x80131539)"
    $Name += "_FileName"
    $TemporaryFile = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $Name

    if ($RuleInfo.Blocked -eq $true) {
        $blockResultUserMode = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"FileName", [Microsoft.SecureBoot.UserConfig.RuleType]"Deny", "FileRule", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
        $blockResultKernel = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"FileName", [Microsoft.SecureBoot.UserConfig.RuleType]"Deny", "FileRule", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
        $ID_User = IncrementDenyID -RuleMap $RuleMap
        $RuleMap = $RuleMap + @{$ID_User=$true}
        $ID_Kernel = IncrementDenyID -RuleMap $RuleMap
        if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
            $RuleMap[$ID_User] = $RuleInfo.Comment
            $RuleMap = $RuleMap + @{$ID_Kernel=$RuleInfo.Comment}
        } else {
            $RuleMap = $RuleMap + @{$ID_Kernel=$true}
        }
        $blockResultUserMode.Id = $ID_User
        $blockResultKernel.Id = $ID_Kernel
        if ($RuleInfo.SpecificFileNameLevel -ne "OriginalFileName") {
            $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
            $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
        } else {
            $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
            $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
        }

        $result += $blockResultUserMode
        $result += $blockResultKernel
    } else {
        if ($RuleInfo.TrustedDriver -eq $true) {
            $kernelResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"FileName", [Microsoft.SecureBoot.UserConfig.RuleType]"Allow", "FileRule", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
            $ID_Kernel = IncrementAllowID -RuleMap $RuleMap
            if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
                $RuleMap = $RuleMap + @{$ID_Kernel=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID_Kernel=$true}
            }
            $kernelResult.ID = $ID_Kernel

            if ($RuleInfo.SpecificFileNameLevel -ne "OriginalFileName") {
                $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
            } else {
                $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
            }

            $result += $kernelResult
        }
        if ($RuleInfo.TrustedUserMode -eq $true) {
            $userModeResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"FileName", [Microsoft.SecureBoot.UserConfig.RuleType]"Allow", "FileRule", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
            $ID_User = IncrementAllowID -RuleMap $RuleMap
            if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
                $RuleMap = $RuleMap + @{$ID_User=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID_User=$true}
            }
            $userModeResult.ID = $ID_User

            if ($RuleInfo.SpecificFileNameLevel -ne "OriginalFileName") {
                $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
            } else {
                $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
            }

            $result += $userModeResult
        }
    }

    return $result,$RuleMap
}

function New-MicrosoftSecureBootCertificateRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $PSModuleRoot
    )

    $HasComment = $false
    if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
        $HasComment = $true       
    }
    $result = @()
    $Name = $RuleInfo.CommonName
    #NOTE: Temporary XML--with the common name and cert TBS hash are copied here. The reason I do this is
    #...because Microsoft doesn't allow you to set the "root" property of a [Microsoft.SecureBoot.UserConfig.Rule] type directly
    $TempFilePath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( "TEMPORARY_PLACEHOLDER_POLICY_DO_NOT_IMPLEMENT.xml")))

    if ($RuleInfo.Blocked -eq $true) {
        $XML_Denied_Driver = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\DeniedSigner_Placeholder_Driver.xml") -ErrorAction Stop
        $XML_Denied_UserMode = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\DeniedSigner_Placeholder_UserMode.xml") -ErrorAction Stop

        $ID = IncrementSignerID -RuleMap $RuleMap
        if ($HasComment) {
            $RuleMap = $RuleMap + @{$ID=$RuleInfo.Comment}
        } else {
            $RuleMap = $RuleMap + @{$ID=$true}
        }
        $ID2 = IncrementSignerID -RuleMap $RuleMap
        if ($HasComment) {
            $RuleMap = $RuleMap + @{$ID2=$RuleInfo.Comment}
        } else {
            $RuleMap = $RuleMap + @{$ID2=$true}
        }

        $XML_Denied_Driver = $XML_Denied_Driver.Replace('<CertPublisher Value="PLACEHOLDER_COMPANY_FAKE_LLC" />','').Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.TBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID)
        $XML_Denied_Driver | Set-Content $TempFilePath -Force -ErrorAction Stop
        $DriverBlockRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

        $XML_Denied_UserMode = $XML_Denied_UserMode.Replace('<CertPublisher Value="PLACEHOLDER_COMPANY_FAKE_LLC" />','').Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.TBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID2)
        $XML_Denied_UserMode | Set-Content $TempFilePath -Force -ErrorAction Stop
        $UserModeBlockRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

        $result += $DriverBlockRule
        $result += $UserModeBlockRule
    } else {
        if ($RuleInfo.TrustedDriver -eq $true) {
            $ID = IncrementSignerID -RuleMap $RuleMap
            if ($HasComment) {
                $RuleMap = $RuleMap + @{$ID=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID=$true}
            }
            $XML_Allowed_Driver = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\AllowedSigner_Placeholder_Driver.xml") -ErrorAction Stop

            $XML_Allowed_Driver = $XML_Allowed_Driver.Replace('<CertPublisher Value="PLACEHOLDER_COMPANY_FAKE_LLC" />','').Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.TBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID)
            $XML_Allowed_Driver | Set-Content $TempFilePath -Force -ErrorAction Stop
            $DriverAllowRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

            $result += $DriverAllowRule
        }
        if ($RuleInfo.TrustedUserMode -eq $true) {
            $ID = IncrementSignerID -RuleMap $RuleMap
            if ($HasComment) {
                $RuleMap = $RuleMap + @{$ID=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID=$true}
            }
            $XML_Allowed_UserMode = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\AllowedSigner_Placeholder_UserMode.xml") -ErrorAction Stop

            $XML_Allowed_UserMode = $XML_Allowed_UserMode.Replace('<CertPublisher Value="PLACEHOLDER_COMPANY_FAKE_LLC" />','').Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.TBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID)
            $XML_Allowed_UserMode | Set-Content $TempFilePath -Force -ErrorAction Stop
            $UserModeAllowRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

            $result += $UserModeAllowRule
        }
    }

    Remove-Item $TempFilePath -ErrorAction SilentlyContinue
    return $result,$RuleMap
}

function New-MicrosoftSecureBootLeafCertificateRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $PSModuleRoot
    )

    #As of now, there is no reasonable difference between a PcaCertificate rule and a LeafCertificate rule (by XML alone)
    $result,$RuleMap = (New-MicrosoftSecureBootCertificateRule -RuleInfo $RuleInfo -RuleMap $RuleMap -PSModuleRoot $PSModuleRoot -ErrorAction Stop)
    return $result,$RuleMap
}

function New-MicrosoftSecureBootPcaCertificateRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $PSModuleRoot
    )

    #As of now, there is no reasonable difference between a PcaCertificate rule and a LeafCertificate rule (by XML alone)
    $result,$RuleMap = (New-MicrosoftSecureBootCertificateRule -RuleInfo $RuleInfo -RuleMap $RuleMap -PSModuleRoot $PSModuleRoot -ErrorAction Stop)
    return $result,$RuleMap
}

function New-MicrosoftSecureBootPublisherRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $PSModuleRoot,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    $result = @()
    $HasComment = $false
    if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
        $HasComment = $true       
    }
    $LeafCommonName = $RuleInfo.LeafCertCN
    $Name = (Get-WDACCertificateCommonName -TBSHash $RuleInfo.PcaCertTBSHash -Connection $Connection -ErrorAction Stop).CommonName
    #NOTE: Temporary XML--with the common name and cert TBS hash are copied here. The reason I do this is
    #...because Microsoft doesn't allow you to set the "root" property of a [Microsoft.SecureBoot.UserConfig.Rule] type directly
    $TempFilePath = (Join-Path $PSModuleRoot -ChildPath (".WDACFrameworkData\" + ( "TEMPORARY_PLACEHOLDER_POLICY_DO_NOT_IMPLEMENT.xml")))

    if ($RuleInfo.Blocked -eq $true) {
        $XML_Denied_Driver = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\DeniedSigner_Placeholder_Driver.xml") -ErrorAction Stop
        $XML_Denied_UserMode = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\DeniedSigner_Placeholder_UserMode.xml") -ErrorAction Stop

        $ID = IncrementSignerID -RuleMap $RuleMap
        if ($HasComment) {
            $RuleMap = $RuleMap + @{$ID=$RuleInfo.Comment}
        } else {
            $RuleMap = $RuleMap + @{$ID=$true}
        }
        $ID2 = IncrementSignerID -RuleMap $RuleMap
        if ($HasComment) {
            $RuleMap = $RuleMap + @{$ID2=$RuleInfo.Comment}
        } else {
            $RuleMap = $RuleMap + @{$ID2=$true}
        }

        $XML_Denied_Driver = $XML_Denied_Driver.Replace('PLACEHOLDER_COMPANY_FAKE_LLC',$LeafCommonName).Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.PcaCertTBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID)
        $XML_Denied_Driver | Set-Content $TempFilePath -Force -ErrorAction Stop
        $DriverBlockRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

        $XML_Denied_UserMode = $XML_Denied_UserMode.Replace('PLACEHOLDER_COMPANY_FAKE_LLC',$LeafCommonName).Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.PcaCertTBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID2)
        $XML_Denied_UserMode | Set-Content $TempFilePath -Force -ErrorAction Stop
        $UserModeBlockRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

        $result += $DriverBlockRule
        $result += $UserModeBlockRule
    } else {
        if ($RuleInfo.TrustedDriver -eq $true) {
            $ID = IncrementSignerID -RuleMap $RuleMap
            if ($HasComment) {
                $RuleMap = $RuleMap + @{$ID=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID=$true}
            }
            $XML_Allowed_Driver = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\AllowedSigner_Placeholder_Driver.xml") -ErrorAction Stop

            $XML_Allowed_Driver = $XML_Allowed_Driver.Replace('PLACEHOLDER_COMPANY_FAKE_LLC',$LeafCommonName).Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.PcaCertTBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID)
            $XML_Allowed_Driver | Set-Content $TempFilePath -Force -ErrorAction Stop
            $DriverAllowRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

            $result += $DriverAllowRule
        }
        if ($RuleInfo.TrustedUserMode -eq $true) {
            $ID = IncrementSignerID -RuleMap $RuleMap
            if ($HasComment) {
                $RuleMap = $RuleMap + @{$ID=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID=$true}
            }
            $XML_Allowed_UserMode = Get-Content (Join-Path $PSModuleRoot -ChildPath ".\Resources\AllowedSigner_Placeholder_UserMode.xml") -ErrorAction Stop

            $XML_Allowed_UserMode = $XML_Allowed_UserMode.Replace('PLACEHOLDER_COMPANY_FAKE_LLC',$LeafCommonName).Replace('ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD',$($RuleInfo.PcaCertTBSHash)).Replace('PLACEHOLDER_COMMON_NAME_FAKE',$Name).Replace('ID_SIGNER_S_1',$ID)
            $XML_Allowed_UserMode | Set-Content $TempFilePath -Force -ErrorAction Stop
            $UserModeAllowRule = (Get-CIPolicy -FilePath $TempFilePath -ErrorAction Stop)[0]

            $result += $UserModeAllowRule
        }
    }

    Remove-Item $TempFilePath -ErrorAction SilentlyContinue
    return $result,$RuleMap
}

function New-MicrosoftSecureBootFilePublisherRule {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $RuleInfo,
        $RuleMap
    )

    $result = @()
    $Name = $RuleInfo.FileName
    #For some reason, using an actual file name with extension results in this error: "Operation is not supported on this platform. (0x80131539)"
    $Name += "_FilePublisherName"
    $TemporaryFile = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $Name

    if ($RuleInfo.Blocked -eq $true) {
        # $TemporaryFile_BlockUserMode = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $blockResultUserMode_TempName
        # $TemporaryFile_BlockKernel = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $blockResultKernel_TempName
        $blockResultUserMode = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"FilePublisher", [Microsoft.SecureBoot.UserConfig.RuleType]"FileAttrib", "FileAttribute", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
        $blockResultKernel = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile, [Microsoft.SecureBoot.UserConfig.RuleLevel]"FilePublisher", [Microsoft.SecureBoot.UserConfig.RuleType]"FileAttrib", "FileAttribute", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
        $ID_User = IncrementFileAttribID -RuleMap $RuleMap
        $RuleMap = $RuleMap + @{$ID_User=$true}
        $ID_Kernel = IncrementFileAttribID -RuleMap $RuleMap
        if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
            $RuleMap[$ID_User] = $RuleInfo.Comment
            $RuleMap = $RuleMap + @{$ID_Kernel=$RuleInfo.Comment}
        } else {
            $RuleMap = $RuleMap + @{$ID_Kernel=$true}
        }
        $blockResultUserMode.Id = $ID_User
        $blockResultKernel.Id = $ID_Kernel
        if ($RuleInfo.SpecificFileNameLevel -ne "OriginalFileName") {
            $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
            $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
        } else {
            $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
            $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
        }

        $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"MinimumFileVersion",$RuleInfo.MinimumAllowedVersion);
        $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"MinimumFileVersion",$RuleInfo.MinimumAllowedVersion);

        $blockResultUserMode.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"MaximumFileVersion",$RuleInfo.MaximumAllowedVersion);
        $blockResultKernel.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"MaximumFileVersion",$RuleInfo.MaximumAllowedVersion);

        $result += $blockResultUserMode
        $result += $blockResultKernel
    } else {

        if ($RuleInfo.TrustedDriver -eq $true) {
            #$TemporaryFile_AllowKernel =  New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $kernelResult_TempName
            $kernelResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $false} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"FilePublisher", [Microsoft.SecureBoot.UserConfig.RuleType]"FileAttrib", "FileAttribute", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
            $ID_Kernel = IncrementFileAttribID -RuleMap $RuleMap
            if (($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
                $RuleMap = $RuleMap + @{$ID_Kernel=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID_Kernel=$true}
            }
            $kernelResult.ID = $ID_Kernel

            if ($RuleInfo.SpecificFileNameLevel -ne "OriginalFileName") {
                $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
            } else {
                $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
            }

            $kernelResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"MinimumFileVersion",$RuleInfo.MinimumAllowedVersion);

            $result += $kernelResult
        }
        if ($RuleInfo.TrustedUserMode -eq $true) {
            #$TemporaryFile_AllowUserMode = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.DriverFile" -ArgumentList $userModeResult_TempName
            $userModeResult = New-Object -TypeName "Microsoft.SecureBoot.UserConfig.Rule" -Property @{UserMode = $true} -ArgumentList ([Microsoft.SecureBoot.UserConfig.DriverFile]$TemporaryFile,[Microsoft.SecureBoot.UserConfig.RuleLevel]"FilePublisher", [Microsoft.SecureBoot.UserConfig.RuleType]"FileAttrib", "FileAttribute", [Microsoft.SecureBoot.UserConfig.FileNameLevel]($RuleInfo.SpecificFileNameLevel))
            $ID_User = IncrementFileAttribID -RuleMap $RuleMap
            if ( ($null -ne $RuleInfo.Comment) -and ("" -ne $RuleInfo.Comment)) {
                $RuleMap = $RuleMap + @{$ID_User=$RuleInfo.Comment}
            } else {
                $RuleMap = $RuleMap + @{$ID_User=$true}
            }
            $userModeResult.ID = $ID_User

            if ($RuleInfo.SpecificFileNameLevel -ne "OriginalFileName") {
                $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]($RuleInfo.SpecificFileNameLevel),$RuleInfo.FileName);
            } else {
                $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"FileName",$RuleInfo.FileName);
            }

            $userModeResult.SetAttribute([Microsoft.SecureBoot.UserConfig.RuleAttribute]"MinimumFileVersion",$RuleInfo.MinimumAllowedVersion);

            $result += $userModeResult
        }
    }

    return $result,$RuleMap
}

Export-ModuleMember -Function New-MicrosoftSecureBootHashRule,New-MicrosoftSecureBootFilePathRule,New-MicrosoftSecureBootFileNameRule,New-MicrosoftSecureBootLeafCertificateRule,New-MicrosoftSecureBootPcaCertificateRule,New-MicrosoftSecureBootPublisherRule,New-MicrosoftSecureBootFilePublisherRule,IncrementAllowID,IncrementDenyID,IncrementSignerID,IncrementFileAttribID,Remove-UnderscoreDigits