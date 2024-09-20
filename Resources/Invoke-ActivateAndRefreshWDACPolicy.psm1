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

function Invoke-ActivateAndRefreshWDACPolicy {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string[]]$Machines,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $CIPolicyFileName,
        $X86_RefreshToolName = $null,
        $AMD64_RefreshToolName = $null,
        $ARM64_RefreshToolName = $null,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $RemoteStagingDirectory,
        [switch]$Signed,
        [switch]$RestartRequired,
        [switch]$ForceRestart,
        [switch]$RemoveUEFI,
        $LocalMachineName
    )

    $sess = New-PSSession -ComputerName $Machines -ErrorAction SilentlyContinue
    
    if (-not $sess) {
        #throw New-Object System.Management.Automation.Remoting.PSRemotingTransportException
        
        #Easier to return null here in all other cases so the transaction is rolled back (rather than having to defer all devices)
        #...In the case that a signed policy becomes unsigned, and NO connection is established after the first temporary signed policy is applied, then that machine IS deferred
        return $null
    }

    $Result = Invoke-Command -Session $sess -ArgumentList $CIPolicyFileName,$RemoteStagingDirectory,$X86_RefreshToolName,$AMD64_RefreshToolName,$ARM64_RefreshToolName,$Signed.ToBool(),$RestartRequired.ToBool(),$ForceRestart.ToBool(),$RemoveUEFI.ToBool(),$LocalMachineName -ScriptBlock {
        Param (
            $CIPolicyFileName,
            $RemoteStagingDirectory,
            $X86_RefreshToolName,
            $AMD64_RefreshToolName,
            $ARM64_RefreshToolName,
            $Signed,
            $RestartRequired,
            $ForceRestart,
            $RemoveUEFI,
            $LocalMachineName
        )

        $ResultMessage = ""
        $WinRMSuccess = $true
        $RefreshToolAndPolicyPresent = $false
        $CopyToCIPoliciesActiveSuccessfull = $false
        $CopyToEFIMount = $false
        $RefreshCompletedSuccessfully = $false
        $ReadyForARestart = $false
        $UEFIRemoveSuccess = $false
        $Windows11 = $false
        $ValidSignature = $false
        $CouldNotRemoveSystem32PolicyFlag = $false
        $Hostname = HOSTNAME.EXE
        $Architecture = cmd.exe /c "echo %PROCESSOR_ARCHITECTURE%"
        #LegacyBIOS means that it is a "non-UEFI" device
        $LegacyBIOS = $false
        if ($env:firmware_type -eq "Legacy") {
            $LegacyBIOS = $true
        }
        $CIPolicyPath = (Join-Path $RemoteStagingDirectory -ChildPath $CIPolicyFileName)
        if ($PSVersionTable.PSEdition -eq "Core") {
            $Windows11 = (Get-CimInstance -Class Win32_OperatingSystem -Property Caption -ErrorAction Stop | Select-Object -ExpandProperty Caption) -Match "Windows 11"
        } elseif ($PSVersionTable.PSEdition -eq "Desktop") {
            $Windows11 = (Get-WmiObject Win32_OperatingSystem -ErrorAction Stop).Caption -Match "Windows 11"
        }
        $RefreshToolPath = $null
        $CiToolPresent = $false
        if ($Windows11 -and (Test-Path "C:\Windows\System32\CiTool.exe")) {
            $CiToolPresent = $true
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

        if ( (Test-Path $CIPolicyPath) -and ((Test-Path $RefreshToolPath) -or $CiToolPresent)) {
            $RefreshToolAndPolicyPresent = $true

            if ($Signed) {
            #If policy is signed, then start to verify that it has a valid signature
                try {
                    if (Test-Path "$env:ProgramFiles\WindowsPowerShell\Modules\Test-ValidWDACSignedPolicySignature\Test-ValidWDACSignedPolicySignature.psm1") {
                        Import-Module "Test-ValidWDACSignedPolicySignature"
                        if (Test-ValidWDACSignedPolicySignature -CISignedPolicyFile $CIPolicyPath) {
                            $ValidSignature = $true
                        } else {
                            throw "Invalid signature for the signed WDAC policy, is invalid for this device."
                        }
                    } else {
                        $ResultMessage += " Signed WDAC policy signature verification checker not present."
                    }
                } catch {
                    $ResultMessage += $_.Exception.Message
                }
            }
        } else {
            $ResultMessage += " No WDAC / CodeIntegrity policy of name $CIPolicyFileName in remote staging directory."
        }


        if ($RefreshToolAndPolicyPresent -and $Signed -and $ValidSignature -and (($null -ne $RefreshToolPath) -or $CiToolPresent)) {
        #Policy is a signed policy (and policy and refresh tool are available)

            if ($CiToolPresent) {
                try {
                    $CiToolUpdateResult = (CiTool --update-policy $CIPolicyPath -json)
                    $UpdateJSON = $CiToolUpdateResult | ConvertFrom-Json
                    if ($UpdateJSON.OperationResult -ne 0) {
                        throw "CiTool returned error $('0x{0:x}' -f [int32]($UpdateJSON).OperationResult)"
                    }
                    $CopyToEFIMount = $true
                } catch {
                    $ResultMessage += ($_ | Format-List -Property * | Out-String)
                    $ResultMessage += " Unable to copy the signed WDAC / code integrity policy to the EFI partition."
                }
            } else {
            #CiTool not present on machine

                if ($LegacyBIOS) {
                #If this device is not UEFI-enabled, copy to the System32 location instead
                    Copy-item -Path $CIPolicyPath -Destination "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -Force -ErrorAction Stop
                    #We set this variable to true even though the device does not have UEFI. It just makes things easier when parsing 
                    #...the results in Deploy-WDACAPolicies
                    $CopyToEFIMount = $true
                } else {
                    try {
                        #Put the signed WDAC policy into the EFI partition 
        
                            #Instructions Provided by Microsoft:
                            #https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/deploy-wdac-policies-with-script
                            $MountPoint = "$env:SystemDrive\EFIMount"
                            $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"
                            #Note: For devices that don't have an EFI System Partition, this will just return the C: drive usually
                            $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]
                            if (-Not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force -ErrorAction Stop | Out-Null }
                            mountvol $MountPoint $EFIPartition | Out-Null
                            if (-Not (Test-Path $EFIDestinationFolder)) { New-Item -Path $EFIDestinationFolder -Type Directory -Force -ErrorAction Stop | Out-Null }
                            #Remove from System32 location first if it exists
                            if (Test-Path (Join-Path "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -ChildPath $CIPolicyFileName)) {
                                Remove-Item -Path (Join-Path "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -ChildPath $CIPolicyFileName) -Force -ErrorAction Stop
                            }
                            Copy-Item -Path $CIPolicyPath -Destination $EFIDestinationFolder -Force -ErrorAction Stop
        
                            mountvol $MountPoint /D | Out-Null
                            $CopyToEFIMount = $true
                        } catch {
                            $ResultMessage += " Unable to copy the signed WDAC / code integrity policy to the EFI partition."
                        }
                }
                
            }

            #Remove the unsigned version of the policy from the System32 location (usually this happens if a policy was unsigned first)
            if ((-not $LegacyBIOS) -and (Test-Path (Join-Path "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -ChildPath $CIPolicyFileName))) {
                #Only remove from System32 location if signed policy successfully copied to EFI mount.
                if ($CopyToEFIMount) {
                    try {
                        Remove-Item -Path (Join-Path "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -ChildPath $CIPolicyFileName) -Force -ErrorAction Stop
                    } catch {
                        $ResultMessage += " !!!!!!!!!!!!! `n ERROR: Unable to remove unsigned policy from System32 location. This might result in a blue-screen! `n !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                        $CouldNotRemoveSystem32PolicyFlag = $true
                        try {
                            Set-Location $RemoteStagingDirectory
                            Get-ChildItem * -Include *.cip | Remove-Item -ErrorAction Stop | Out-Null
                        } catch {
                            $ResultMessage += " Trouble with deleting previous .CIP files in WDAC staging directory."
                        }
                        $Result = @()
                        $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshToolAndPolicyPresent = $RefreshToolAndPolicyPresent; CopyToEFIMount = $CopyToEFIMount; CouldNotRemoveSystem32PolicyFlag = $CouldNotRemoveSystem32PolicyFlag}
                        return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
                    }
                }
            }

        } elseif ($RefreshToolAndPolicyPresent -and (($null -ne $RefreshToolPath) -or $CiToolPresent)) {
        #Policy is NOT a signed policy (and policy and refresh tool are available)

            if ($CiToolPresent) {
                try {
                    $CiToolUpdateResult = (CiTool --update-policy $CIPolicyPath -json)
                    $UpdateJSON = $CiToolUpdateResult | ConvertFrom-Json
                    if ($UpdateJSON.OperationResult -ne 0) {
                        throw "CiTool returned error $('0x{0:x}' -f [int32]($UpdateJSON).OperationResult)"
                    }
                    $CopyToCIPoliciesActiveSuccessfull = $true
                } catch {
                    $ResultMessage += ($_ | Format-List -Property * | Out-String)
                    $ResultMessage += " Unable to copy WDAC / Code integrity policy to $($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active\"
                }
            } else {
                try {
                    Copy-item -Path $CIPolicyPath -Destination "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -Force -ErrorAction Stop
                    $CopyToCIPoliciesActiveSuccessfull = $true
                } catch {
                    $ResultMessage += " Unable to copy WDAC / Code integrity policy to $($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active\"
                }
            }

            if ($RemoveUEFI) {

                try {
                    #Part of the functionallity is pulled from this Microsoft help page:
                    #https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/disable-wdac-policies

                    $MountPoint = "$env:SystemDrive\EFIMount"
                    $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"

                    #Note: For devices that don't have an EFI System Partition, this will just return the C: drive usually
                    $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]

                    if (-not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force -ErrorAction Stop | Out-Null }
                    mountvol $MountPoint $EFIPartition | Out-Null

                    if (Test-Path (Join-Path $EFIDestinationFolder -ChildPath $CIPolicyFileName)) {
                        if ($CiToolPresent) {
                            $ResultMessage += " CiTool didn't remove the policy from the EFI partition when deploying the unsigned policy."
                        }
                        Remove-Item -Path (Join-Path $EFIDestinationFolder -ChildPath $CIPolicyFileName) -Force -ErrorAction Stop | Out-Null
                        mountvol $MountPoint /D | Out-Null
                        $UEFIRemoveSuccess = $true
                    } else {
                        if (-not $CiToolPresent) {
                            #This means that we expected a signed policy to be in the EFI partition based on all previous history, and it isn't there and it should be.
                            $ResultMessage += " UEFI-partitioned policy file not in the expected place for some reason."
                        } else {
                            #If the CiTool is on the machine, we'll assume that CiTool was able to successfully remove it.
                            $UEFIRemoveSuccess = $true
                        }
                        mountvol $MountPoint /D | Out-Null
                    }
                } catch {
                    $ResultMessage += ("Unable to remove signed WDAC policy from the EFI partition: " + $_)
                }
            }
        }

        if (($Signed -and $CopyToEFIMount -and $RefreshToolAndPolicyPresent) -or ((-not $Signed) -and $CopyToCIPoliciesActiveSuccessfull -and $RefreshToolAndPolicyPresent)) {
            
            if ($RestartRequired) {
            #If this is the first time a signed policy has been deployed on the system, and memory integrity is enabled, then a restart of the system is required
            #...rather than using the refresh tool to activate the policy
                $ProceedForceRestart = $true
                if ($LocalMachineName -and $Hostname) {
                    if ($LocalMachineName -eq $Hostname) {
                        $ProceedForceRestart = $false
                    }
                }
                if ($ForceRestart -and $ProceedForceRestart) {
                    try {
                    #Log out every user
                        
                        ## Find all sessions matching the specified username
                        $sessions = quser

                        if ($sessions -and ($sessions.Count -ge 1)) {
                            #Take out the Headers
                            $sessions = $sessions[1..($sessions.count-1)]

                            ## Parse the session IDs from the output
                            $sessionIds = @()
                            for ($i=0; $i -lt $sessions.Count; $i++) {
                                $sessionIds += ($sessions[$i] -split ' +')[2]
                            }

                            ## Loop through each session ID and pass each to the logoff command
                            $sessionIds | ForEach-Object {
                                try {
                                    Start-Process logoff -ArgumentList "$_" -Wait -ErrorAction Stop
                                } catch {
                                    if ($_.Exception.Message -match 'No user exists') {
                                        #The user is not logged in
                                        continue
                                    } else {
                                        throw $_
                                    }
                                }
                            }
                        }

                        $ReadyForARestart = $true
                        $ResultMessage += " Device will need to be restarted to apply policy; users logged out and device is ready for a restart."
                    } catch {                                   
                        $ResultMessage += ("Error while logging users out to prep device for restart to activate policy: " + $_)
                        try {
                            Set-Location $RemoteStagingDirectory
                            Get-ChildItem * -Include *.cip | Remove-Item -ErrorAction Stop | Out-Null
                        } catch {
                            $ResultMessage += " Trouble with deleting previous .CIP files in WDAC staging directory."
                        }
                        $Result = @()
                        $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshToolAndPolicyPresent = $RefreshToolAndPolicyPresent; CopyToCIPoliciesActiveSuccessfull = $CopyToCIPoliciesActiveSuccessfull; CopyToEFIMount = $CopyToEFIMount; RefreshCompletedSuccessfully = $RefreshCompletedSuccessfully; ReadyForARestart = $ReadyForARestart}
                        return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
                    }
                } else {
                    $ReadyForARestart = $true
                    $ResultMessage += " Device will need to be restarted to apply policy."
                }


            } else {
            #Restart not required, proceed with refresh

                try {
                    if ($CiToolPresent) {
                        $CiToolRefreshResult = (CiTool --refresh -json)
                        $RefreshJSON = $CiToolRefreshResult | ConvertFrom-Json
                        if ($RefreshJSON.OperationResult -ne 0) {
                            throw "CiTool returned error $('0x{0:x}' -f [int32]($RefreshJSON).OperationResult)"
                        }
                        $RefreshCompletedSuccessfully = $true
                        $ResultMessage += " Refresh completed successfully."
                    } elseif ($null -ne $RefreshToolPath) {
                        Start-Process $RefreshToolPath -NoNewWindow -Wait -ErrorAction Stop
                        $RefreshCompletedSuccessfully = $true
                        $ResultMessage += " Refresh completed successfully."
                    } else {
                        $ResultMessage += " Unable to find the wherewithal to run a refresh on WDAC policies."
                    }
                } catch {
                    $ResultMessage += ($_ | Format-List -Property * | Out-String)
                    $ResultMessage += " Refresh job was unsuccessful."
                }
            }
        }

        try {
            Set-Location $RemoteStagingDirectory -ErrorAction Stop
            Get-ChildItem * -Include *.cip | Remove-Item -ErrorAction Stop | Out-Null
        } catch {
            $ResultMessage += " Trouble with deleting previous .CIP files in WDAC staging directory."
        }

        $Result = @()
        $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshToolAndPolicyPresent = $RefreshToolAndPolicyPresent; CopyToCIPoliciesActiveSuccessfull = $CopyToCIPoliciesActiveSuccessfull; CopyToEFIMount = $CopyToEFIMount; RefreshCompletedSuccessfully = $RefreshCompletedSuccessfully; ReadyForARestart = $ReadyForARestart; UEFIRemoveSuccess = $UEFIRemoveSuccess}
        return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
    } -ErrorAction SilentlyContinue


    return $Result
}

Export-ModuleMember -Function Invoke-ActivateAndRefreshWDACPolicy