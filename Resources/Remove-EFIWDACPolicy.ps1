function Get-X86Path {
    $X86_Path = (Get-LocalStorageJSON -ErrorAction Stop)."RefreshTool_x86"
    if (-not $X86_Path -or ("" -eq $X86_Path)) {
        throw "For remote machines with AMD64 architecture, specify the path of the AMD64 refresh tool in LocalStorage.json."
    }
    if (-not (Test-Path $X86_Path)) {
        throw "Please provide the full, valid path of the X86 refresh tool executable in LocalStorage.json."
    }

    return $X86_Path
}

function Get-AMD64Path {
    
    $AMD64_Path = (Get-LocalStorageJSON -ErrorAction Stop)."RefreshTool_AMD64"
    if (-not $AMD64_Path -or ("" -eq $AMD64_Path)) {
        throw "For remote machines with AMD64 architecture, specify the path of the AMD64 refresh tool in LocalStorage.json."
    }
    if (-not (Test-Path $AMD64_Path)) {
        throw "Please provide the full, valid path of the AMD64 refresh tool executable in LocalStorage.json."
    }

    return $AMD64_Path
}

function Get-ARM64Path {
    $ARM64_Path = (Get-LocalStorageJSON -ErrorAction Stop)."RefreshTool_ARM64"
    if (-not $ARM64_Path -or ("" -eq $ARM64_Path)) {
        throw "For remote machines with ARM64 architecture, specify the path of the ARM64 refresh tool in LocalStorage.json."
    }
    if (-not (Test-Path $ARM64_Path)) {
        throw "Please provide the full, valid path of the ARM64 refresh tool executable in LocalStorage.json."
    }

    return $ARM64_Path
}

function Remove-EFIWDACPolicy {
#WARNING: You should only remove a policy from the EFI partition if you've successfully replaced it with a signed policy with the option "Enabled:Unsigned System Integrity Policy" enabled.
    
    <#
    .SYNOPSIS
    If some devices successfully applied a recently unsigned policy (where that same policy was previously signed),
    but the old signed policy was unsuccessfully removed from the EFI Partion, then run this cmdlet. 
    WARNING: You should only remove a policy from the EFI partition if you've successfully replaced it 
    with a signed policy with the option "Enabled:Unsigned System Integrity Policy" enabled.
    
    .DESCRIPTION
    Usually this cmdlet should only be run if the Deploy-WDACPolicies or Restore-WDACWorkstations says that you should,
    which is only when a new unsigned policy is placed in this folder: C:\Windows\System32\CodeIntegrity\CiPolicies\Active
    but the policy in the EFI mount is not removed

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER Devices
    The devices you want to remove the EFI boot policy from

    .PARAMETER PolicyGUID
    The policy you would specifically like to remove from the EFI partition

    .PARAMETER Refresh
    Use this switch if you'd also like to run a refresh on the devices after removing the policy from the EFI partition
    #>
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("PC","Computer","Computers","Device","PCs","Workstation","Workstations")]
        [string[]]$Devices,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $PolicyGUID,
        [switch]$Refresh
    )

    $X86_Path = $null
    $AMD64_Path = $null
    $ARM64_Path = $null
    $X86_RefreshToolName = $null
    $AMD64_RefreshToolName = $null
    $ARM64_RefreshToolName = $null
    $RemoteStagingDirectory = $null

    if ($Refresh) {
        foreach ($Machine in $Devices) {
            $CPU = Get-WDACWorkstationProcessorArchitecture -DeviceName $Machine -ErrorAction Stop

            if ($CPU -eq "AMD64") {
                if ($null -eq $AMD64_Path) {
                    $AMD64_Path = Get-AMD64Path
                }
            } elseif ($CPU -eq "ARM64") {
                if ($null -eq $ARM64_Path) {
                    $ARM64_Path = Get-ARM64Path
                }
            } elseif ($CPU -eq "X86") {
                if ($null -eq $X86_Path) {
                    $X86_Path = Get-X86Path
                }
            } else {
                #The reason we commit here is because database values were written for CPU architectures
                throw "$CPU CPU architecture not supported for device $thisComputer"
            }
        }

        $RemoteStagingDirectory = (Get-LocalStorageJSON -ErrorAction Stop)."RemoteStagingDirectory"
        if (-not $RemoteStagingDirectory -or ("" -eq $RemoteStagingDirectory)) {
            throw "When using the -Refresh action, you must designate a RemoteStagingDirectory in LocalStorage.json."
        }

        try {
            Split-Path $RemoteStagingDirectory -Qualifier -ErrorAction Stop | Out-Null
        } catch {
            throw "The RemoteStagingDirectory located in LocalStorage.json must have a qualifier such as `"C:\`" or `"D:\`" at the beginning."
        }

        if ($X86_Path -and (-not $X86_RefreshToolName)) {
            $X86_RefreshToolName = Split-Path $X86_Path -Leaf
        }
        if ($AMD64_Path -and (-not $AMD64_RefreshToolName)) {
            $AMD64_RefreshToolName = Split-Path $AMD64_Path -Leaf
        }
        if ($ARM64_Path -and (-not $ARM64_RefreshToolName)) {
            $ARM64_RefreshToolName = Split-Path $ARM64_Path -Leaf
        }
    }

    try {
        if (Test-WDACPolicySigned -PolicyGUID $PolicyGUID -ErrorAction Stop) {
            throw "WDAC policy $PolicyGUID is currently set with a signed status, and should not be removed from the EFI partition."
        }
    } catch {
        Write-Verbose ($_ | Format-List -Property * | Out-String)
        throw "Cannot receive signed status of WDAC policy from DB."
    }

    $X86_Path = $null
    $AMD64_Path = $null
    $ARM64_Path = $null
    $CIPolicyFileName = "{$PolicyGUID}.cip"
    $sess = New-PSSession -ComputerName $Devices -ErrorAction SilentlyContinue

    $Result = Invoke-Command -Session $sess -ArgumentList $X86_RefreshToolName,$AMD64_RefreshToolName,$ARM64_RefreshToolName,$RemoteStagingDirectory,$CIPolicyFileName,$Refresh.ToBool() -ScriptBlock {
        Param (
            $X86_RefreshToolName,
            $AMD64_RefreshToolName,
            $ARM64_RefreshToolName,
            $RemoteStagingDirectory,
            $CIPolicyFileName,
            $Refresh
        )

        $Architecture = cmd.exe /c "echo %PROCESSOR_ARCHITECTURE%"
        $RefreshToolPath = $null
        $ResultMessage = ""
        $Windows11 = $false
        $WinRMSuccess = $true
        $RefreshCompletedSuccessfully = $false
        $UEFIRemoveSuccess = $false

        if ($Refresh) {
            if ($PSVersionTable.PSEdition -eq "Core") {
                $Windows11 = (Get-CimInstance -Class Win32_OperatingSystem -Property Caption -ErrorAction Stop | Select-Object -ExpandProperty Caption) -Match "Windows 11"
            } elseif ($PSVersionTable.PSEdition -eq "Desktop") {
                $Windows11 = (Get-WmiObject Win32_OperatingSystem -ErrorAction Stop).Caption -Match "Windows 11"
            }

            if ($Architecture -eq "X86") {
                if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $X86_RefreshToolName)) {
                    $RefreshToolPath = (Join-Path $RemoteStagingDirectory -ChildPath $X86_RefreshToolName)
                } else {
                    if (-not $Windows11) {
                        $ResultMessage += "No refresh tool present for $Architecture CPU Architecture."
                    }
                }
            } elseif ($Architecture -eq "AMD64") {
                if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $AMD64_RefreshToolName)) {
                    $RefreshToolPath = (Join-Path $RemoteStagingDirectory -ChildPath $AMD64_RefreshToolName)
                } else {
                    if (-not $Windows11) {
                        $ResultMessage += "No refresh tool present for $Architecture CPU Architecture."
                    }
                }
            } elseif ($Architecture -eq "ARM64") {
                if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $ARM64_RefreshToolName)) {
                    $RefreshToolPath = (Join-Path $RemoteStagingDirectory -ChildPath $ARM64_RefreshToolName)
                } else {
                    if (-not $Windows11) {
                        $ResultMessage += "No refresh tool present for $Architecture CPU Architecture."
                    }
                }
            }
        }


        try {
            #Part of the functionallity is pulled from this Microsoft help page:
            #https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/disable-wdac-policies

            $MountPoint = "$SysDrive\EFIMount"
            $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"

            #Note: For devices that don't have an EFI System Partition, this will just return the C: drive usually
            $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]

            if (-Not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force -ErrorAction Stop | Out-Null }
            mountvol $MountPoint $EFIPartition | Out-Null

            if (Test-Path (Join-Path $EFIDestinationFolder -ChildPath $CIPolicyFileName)) {
                Remove-Item -Path (Join-Path $EFIDestinationFolder -ChildPath $CIPolicyFileName) -Force -ErrorAction Stop | Out-Null
                $UEFIRemoveSuccess = $true
            } else {
                $ResultMessage += "Policy file is not present in the EFI partition. (Verify if this should be the case)."
            }
        } catch {
            $ResultMessage += ("Unable to remove signed WDAC policy from the UEFI partition: " + $_)
        }


        if ($Refresh -and $UEFIRemoveSuccess) {
            try {
                if ($null -ne $RefreshToolPath) {
                    Start-Process $RefreshToolPath -NoNewWindow -Wait -ErrorAction Stop
                    $RefreshCompletedSuccessfully = $true
                    $ResultMessage += "Refresh completed successfully."
                } elseif ($Windows11) {
                    #CiTool --update-policy $PolicyDest
                    #I'm not sure if this is redundant or not since we are copying to the CiPolicies\Active folder. Leaving commented for now.

                    CiTool --refresh
                    $RefreshCompletedSuccessfully = $true
                    $ResultMessage += "Refresh completed successfully."
                } else {
                    $ResultMessage += "Unable to find the wherewithal to run a refresh on WDAC policies."
                }
            } catch {
                $ResultMessage += "Refresh job was unsuccessful."
            }

            $Result = @()
            $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshCompletedSuccessfully = $RefreshCompletedSuccessfully; UEFIRemoveSuccess = $UEFIRemoveSuccess}
            return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
        } elseif ($Refresh) {
            $Result = @()
            $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshCompletedSuccessfully = $RefreshCompletedSuccessfully; UEFIRemoveSuccess = $UEFIRemoveSuccess}
            return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
        } else {
            $Result = @()
            $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; UEFIRemoveSuccess = $UEFIRemoveSuccess}
            return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
        }

    } -ErrorAction SilentlyContinue

    if ($Refresh) {
        $Result | Select-Object PSComputerName,ResultMessage,WinRMSuccess,RefreshCompletedSuccessfully,UEFIRemoveSuccess | Format-List -Property *
    } else {
        $Result | Select-Object PSComputerName,ResultMessage,WinRMSuccess,UEFIRemoveSuccess | Format-List -Property *
    }
}