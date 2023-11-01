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
        [switch]$ForceRestart
    )

    $sess = New-PSSession -ComputerName $Machines -ErrorAction SilentlyContinue
    
    if (-not $sess) {
        throw New-Object System.Management.Automation.Remoting.PSRemotingTransportException
    }

    $Result = Invoke-Command -Session $sess -ArgumentList $CIPolicyFileName,$RemoteStagingDirectory,$X86_RefreshToolName,$AMD64_RefreshToolName,$ARM64_RefreshToolName,$Signed.ToBool(),$RestartRequired.ToBool(),$ForceRestart.ToBool() -ScriptBlock {
        Param (
            $CIPolicyFileName,
            $RemoteStagingDirectory,
            $X86_RefreshToolName,
            $AMD64_RefreshToolName,
            $ARM64_RefreshToolName,
            $Signed,
            $RestartRequired,
            $ForceRestart
        )

        $ResultMessage = $null
        $WinRMSuccess = $true
        $RefreshToolAndPolicyPresent = $false
        $CopyToCIPoliciesActiveSuccessfull = $false
        $CopyToEFIMount = $false
        $RefreshCompletedSuccessfully = $false
        $ReadyForARestart = $false
        $Windows11 = $false
        $SysDrive = $null
        $Architecture = cmd.exe /c "echo %PROCESSOR_ARCHITECTURE%"
        if ($PSVersionTable.PSEdition -eq "Core") {
            $Windows11 = (Get-CimInstance -Class Win32_OperatingSystem -Property Caption | Select-Object -ExpandProperty Caption) -Match "Windows 11"
            $SysDrive =  (Get-CimInstance -Class Win32_OperatingSystem -ComputerName localhost -Property SystemDrive | Select-Object -ExpandProperty SystemDrive)
        } elseif ($PSVersionTable.PSEdition -eq "Desktop") {
            $Windows11 = (Get-WmiObject Win32_OperatingSystem).Caption -Match "Windows 11"
            $SysDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
        }
        $RefreshToolPath = $null
        
        if ($Architecture -eq "X86") {
            if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $X86_RefreshToolName)) {
                $RefreshToolPath = (Join-Path $RemoteStagingDirectory -ChildPath $X86_RefreshToolName)
            } else {
                if (-not $Windows11) {
                    $ResultMessage = "No refresh tool present for $Architecture CPU Architecture."
                }
            }
        } elseif ($Architecture -eq "AMD64") {
            if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $AMD64_RefreshToolName)) {
                $RefreshToolPath = (Join-Path $RemoteStagingDirectory -ChildPath $AMD64_RefreshToolName)
            } else {
                if (-not $Windows11) {
                    $ResultMessage = "No refresh tool present for $Architecture CPU Architecture."
                }
            }
        } elseif ($Architecture -eq "ARM64") {
            if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $ARM64_RefreshToolName)) {
                $RefreshToolPath = (Join-Path $RemoteStagingDirectory -ChildPath $ARM64_RefreshToolName)
            } else {
                if (-not $Windows11) {
                    $ResultMessage = "No refresh tool present for $Architecture CPU Architecture."
                }
            }
        }
        
        if ( ($null -ne $RefreshToolPath) -or $Windows11) {
            if (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath $CIPolicyFileName)) {

                $CIPolicyPath = (Join-Path $RemoteStagingDirectory -ChildPath $CIPolicyFileName)
                $RefreshToolAndPolicyPresent = $true

                try {
                    Copy-item -Path $CIPolicyPath -Destination "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -Force -ErrorAction Stop
                    $CopyToCIPoliciesActiveSuccessfull = $true
                } catch {
                    $ResultMessage = "Unable to copy WDAC / Code integrity policy to $($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active\"
                }


                if ($CopyToCIPoliciesActiveSuccessfull) {

                    if ($Signed) {
                        try {
                        #Put the signed WDAC policy into the UEFI partition 

                            #Instructions Provided by Microsoft:
                            #https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/deploy-wdac-policies-with-script
                            $MountPoint = "$SysDrive\EFIMount"
                            $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"
                            $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]
                            if (-Not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force -ErrorAction Stop }
                            mountvol $MountPoint $EFIPartition
                            if (-Not (Test-Path $EFIDestinationFolder)) { New-Item -Path $EFIDestinationFolder -Type Directory -Force -ErrorAction Stop }

                            Copy-Item -Path $CIPolicyPath -Destination $EFIDestinationFolder -Force -ErrorAction Stop

                            $CopyToEFIMount = $true
                        } catch {
                            $ResultMessage = "Unable to copy the signed WDAC / code integrity policy to the UEFI partition."
                        }
                    }

                    if ((-not $Signed) -or ($Signed -and $CopyToEFIMount)) {
                    #Run a refresh or prepare a restart

                        #$PolicyDest = Join-Path "$($Env:Windir)\System32\CodeIntegrity\CiPolicies\Active" -ChildPath $CIPolicyFileName
                        
                        if ($RestartRequired) {
                        #If this is the first time a signed policy has been deployed on the system, and memory integrity is enabled, then a restart of the system is required
                        #...rather than using the refresh tool to activate the policy

                            if ($ForceRestart) {
                                try {
                                #Log out every user
                                    
                                    ## Find all sessions matching the specified username
                                    $sessions = quser

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

                                    $ReadyForARestart = $true
                                    $ResultMessage = "Device will need to be restarted to apply policy; users logged out and device is ready for a restart."
                                } catch {                                   
                                    $ResultMessage = ("Error while logging users out to prep device for restart to activate policy: " + $_)
                                    try {
                                        Set-Location $RemoteStagingDirectory
                                        Get-ChildItem * -Include *.cip | Remove-Item -ErrorAction Stop
                                    } catch {
                                        $ResultMessage += " Trouble with deleting previous .CIP files in WDAC staging directory."
                                    }
                                    $Result = @()
                                    $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshToolAndPolicyPresent = $RefreshToolAndPolicyPresent; CopyToCIPoliciesActiveSuccessfull = $CopyToCIPoliciesActiveSuccessfull; CopyToEFIMount = $CopyToEFIMount; RefreshCompletedSuccessfully = $RefreshCompletedSuccessfully; ReadyForARestart = $ReadyForARestart}
                                    return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
                                }
                            } else {
                                $ReadyForARestart = $true
                                $ResultMessage = "Device will need to be restarted to apply policy."
                            }

                        } else {
                            try {
                                if ($null -ne $RefreshToolPath) {
                                    Start-Process $RefreshToolPath -Wait -ErrorAction Stop
                                    $RefreshCompletedSuccessfully = $true
                                } elseif ($Windows11) {
                                    #CiTool --update-policy $PolicyDest
                                    #I'm not sure if this is redundant or not since we are copying to the CiPolicies\Active folder. Leaving commented for now.

                                    CiTool --refresh
                                    $RefreshCompletedSuccessfully = $true
                                } else {
                                    $ResultMessage = "Unable to find the wherewithal to run a refresh on WDAC policies."
                                }
                            } catch {
                                $ResultMessage = "Refresh job was unsuccessful."
                            }
                        }
                        
                    }
                }

            } else {
                $ResultMessage = "No WDAC / CodeIntegrity policy of name $CIPolicyFileName in remote staging directory."
            }
        }

        try {
            Set-Location $RemoteStagingDirectory -ErrorAction Stop
            Get-ChildItem * -Include *.cip | Remove-Item -ErrorAction Stop
        } catch {
            $ResultMessage += " Trouble with deleting previous .CIP files in WDAC staging directory."
        }

        $Result = @()
        $Result += @{WinRMSuccess = $WinRMSuccess; ResultMessage = $ResultMessage; RefreshToolAndPolicyPresent = $RefreshToolAndPolicyPresent; CopyToCIPoliciesActiveSuccessfull = $CopyToCIPoliciesActiveSuccessfull; CopyToEFIMount = $CopyToEFIMount; RefreshCompletedSuccessfully = $RefreshCompletedSuccessfully; ReadyForARestart = $ReadyForARestart}
        return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
    } -ErrorAction SilentlyContinue


    return $Result
}