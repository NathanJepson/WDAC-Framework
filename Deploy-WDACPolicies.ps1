function Deploy-WDACPolicies {
    <#
    .SYNOPSIS
    This function deploys WDAC policies specified by parameter input -- 
    ONLY IF the latest version hasn't yet been deployed -- signs them (if applicable)
    and copies them to the relevant machines which have those policies assigned.
    Then a RefreshPolicy action is enacted on that machine.

    .DESCRIPTION
    This function determines what machines have the designated policy assigned to them, by checking the policy "pillar" attribute, 
    as well as group assignments and ad-hoc assignments. (A policy set as a pillar is deployed to every device listed in the trust database.)
    It signs policies which need to be signed. (Using the SignTool.)
    Then, that designated policy (the signed / unsigned .CIP file) is deployed to each machine (ONLY IF the DB shows that that version has not been deployed yet.)
    For machines which cannot have their policy updated, the last deployed policy is recorded -- with all its parameters, in the deferred_policies table, 
    and an entry for that particular device is made in the deferred_policies_assignments table.
    Then, if a policy is signed, it is also placed in the UEFI partition for the machine.
    Finally, a refresh policy is performed on the relevant machine (if the machine runs on Windows 11, the CiTool is used, otherwise, RefreshPolicy.exe is used.)
    When a selection of TestComputers is designated, the remaining computers which are not test computers are set with the policy_deferring flag until the 
    Restore-WDACWorkstations cmdlet is used to bring those computers up-to-date with the most recent policy version.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER PolicyGUID
    ID of the policy (NOT the alternate ID which WDAC policies also have, although you can use the alias "PolicyID" for this parameter)

    .PARAMETER PolicyName
    Name of the policy (exact)

    .PARAMETER Local
    Use this switch if you merely want to update the policy on your current machine (local)

    .PARAMETER TestComputers
    Specify test computers where you would like to deploy the policy first. First, a check is performed if a test computer is actually assigned the particular policy.
    Once you can verify that a policy was successfully deployed on the test machines, then run the Restore-WDACWorkstations cmdlet to deploy the relevant policy
    to the remaining machines which have the policy assigned.

    .PARAMETER TestForce
    Force deployment of policy to machines -- even if they are not assigned the relevant policy. (Only if "TestComputers" is provided.)

    .PARAMETER SkipSetup
    Cmdlet will not check whether staging directory or refresh tools are present on a device.

    .PARAMETER ForceRestart
    WARNING: Disruptive action.
    All devices* will be forced to restart! -- *Only applies to when a signed base policy is 
    deployed on a device for the first time.

    .EXAMPLE
    TODO

    .EXAMPLE
    TODO
    #>    
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Alias("PolicyID","id")]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,
        [switch]$Local,
        [Alias("TestMachines","TestMachine","TestDevices","TestDevice","TestComputer")]
        [string[]]$TestComputers,
        [Alias("Force")]
        [switch]$TestForce,
        [switch]$SkipSetup,
        [switch]$ForceRestart
    )
    
    if ($PolicyName -and $PolicyGUID) {
        throw "Cannot provide both a policy name and policy GUID."
    }

    if ($TestForce -and (-not $TestComputers)) {
        throw "Cannot set TestForce without providing a list of test computers."
    }

    if (-not $Local) {
        $RemoteStagingDirectory = (Get-LocalStorageJSON -ErrorAction Stop)."RemoteStagingDirectory"
        if (-not $RemoteStagingDirectory -or ("" -eq $RemoteStagingDirectory)) {
            throw "When deploying staged policies to remote machines, you must designate a RemoteStagingDirectory in LocalStorage.json."
        }

        try {
            Split-Path $RemoteStagingDirectory -Qualifier -ErrorAction Stop | Out-Null
        } catch {
            throw "The RemoteStagingDirectory must have a qualifier such as `"C:\`" or `"D:\`" at the beginning."
        }
    }

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        
        if ($PolicyName) {
            $PolicyInfo = Get-WDACPolicyByName -PolicyName $PolicyName -Connection $Connection
            $PolicyGUID = $PolicyInfo.PolicyGUID
        } elseif ($PolicyGUID) {
            $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection
        }

    
        if ($Local) {
            #TODO

        } else {
        #Push to Remote Machines

            if (($null -ne $PolicyInfo.PolicyVersion) -and ($null -ne $PolicyInfo.LastDeployedPolicyVersion)) {
                if ((Test-ValidVersionNumber -VersionNumber $PolicyInfo.PolicyVersion) -and (Test-ValidVersionNumber -VersionNumber $PolicyInfo.LastDeployedPolicyVersion)) {
                    if ((Compare-Versions -Version1 $PolicyInfo.PolicyVersion -Version2 $PolicyInfo.LastDeployedPolicyVersion) -le  0) {
                        throw "Latest version of this policy is already deployed."
                    }
                }
            }

            if ($PolicyInfo.IsPillar -eq $true) {
                $ComputerMap = Get-WDACDevicesAllNamesAndCPUInfo -Connection $Connection -ErrorAction Stop
            } else {
                $ComputerMap = Get-WDACDevicesNeedingWDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            }

            if ( (($null -eq $ComputerMap) -or $ComputerMap.Count -le 0) -and (-not ($TestComputers -and $TestForce)) ) {
                throw "No non-deferred workstations currently assigned to policy $PolicyGUID"
            }

            $PolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            $SignedToUnsigned = Test-MustRemoveSignedPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
            $X86_Path = $null
            $AMD64_Path = $null
            $ARM64_Path = $null

            if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
                $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
                Write-Verbose "The current file is in the SignedModules folder."
            } else {
                $PSModuleRoot = $PSScriptRoot
            }        

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

            $NewComputerMap = @()

            foreach ($Computer in $ComputerMap.GetEnumerator()) {
                $thisComputer = $Computer.Name
                $CPU = $Computer.Value
                
                if ($null -eq $CPU -or ($CPU -eq "") -or ($CPU -is [System.DBNull])) {
                    $Architecture = $null
                    try {
                        $Architecture = Invoke-Command -ComputerName $thisComputer -ScriptBlock {cmd.exe /c "echo %PROCESSOR_ARCHITECTURE%"} -ErrorAction Stop
                    } catch {
                        Write-Verbose "Device $thisComputer not available for PowerShell remoting."
                        $NewComputerMap += @{DeviceName = $thisComputer; CPU = $CPU; NewlyDeferred = $true; TestMachine = $false}
                        continue
                    }

                    if ($Architecture) {
                        if (-not (Add-WDACWorkstationProcessorArchitecture -DeviceName $thisComputer -ProcessorArchitecture $Architecture -Connection $Connection -ErrorAction Stop)) {
                            Write-Verbose "Could not write CPU architecture $Architecture of device $thisComputer to database."
                        }
                        $CPU = $Architecture
                    }
                }

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
                    $Transaction.Commit()
                    $Connection.Close()
                    throw "$CPU CPU architecture not supported for device $thisComputer"
                }

                if ($TestComputers) {
                    if ( ($TestComputers -contains $thisComputer)) {
                        $NewComputerMap += @{DeviceName = $thisComputer; CPU = $CPU; NewlyDeferred = $false; TestMachine = $true}
                    } else {
                        $NewComputerMap += @{DeviceName = $thisComputer; CPU = $CPU; NewlyDeferred = $true; TestMachine = $false}
                    }
                } else {
                    $NewComputerMap += @{DeviceName = $thisComputer; CPU = $CPU; NewlyDeferred = $false; TestMachine = $false}
                }
            }

            if ($TestForce) {  
                foreach ($thisTestMachine in $TestComputers) {
                    $Assigned = $false
                    $CPU = $null
                    foreach ($Computer in $ComputerMap.GetEnumerator()) {
                        if ($thisTestMachine -eq $Computer.Name) {
                            $Assigned = $true
                        }
                    }
                    if (-not $Assigned) {
                        
                        #$NewComputerMap += @{DeviceName = $thisTestMachine; CPU = }
                        $CPU = Get-WDACWorkstationProcessorArchitecture -DeviceName $thisTestMachine -Connection $Connection -ErrorAction Stop
                        if ($null -eq $CPU -or ($CPU -eq "") -or ($CPU -is [System.DBNull])) {
                            $Architecture = $null
                            try {
                                $Architecture = Invoke-Command -ComputerName $thisComputer -ScriptBlock {cmd.exe /c "echo %PROCESSOR_ARCHITECTURE%"} -ErrorAction Stop
                            } catch {
                                Write-Verbose "Device $thisComputer not available for PowerShell remoting."
                                #We don't add this device to the $NewComputerMap because it was never assigned the policy in the first place and we don't want to defer it
                                continue
                            }
        
                            if ($Architecture) {
                                if (-not (Add-WDACWorkstationProcessorArchitecture -DeviceName $thisComputer -ProcessorArchitecture $Architecture -Connection $Connection -ErrorAction Stop)) {
                                    Write-Verbose "Could not write CPU architecture $Architecture of device $thisComputer to database."
                                }
                                $CPU = $Architecture
                            } elseif (($null -eq $Architecture) -or ("" -eq $Architecture)) {
                                Write-Verbose "Could not retrieve valid CPU architecture from $thisComputer"
                                continue
                            }
                        }

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
                        } elseif (($null -ne $CPU) -and ("" -ne $CPU)) {
                            #The reason we commit here is because database values were written for CPU architectures
                            $Transaction.Commit()
                            $Connection.Close()
                            throw "$CPU CPU architecture not supported for device $thisComputer"
                        }

                        if ($CPU) {
                            $NewComputerMap += @{DeviceName = $thisComputer; CPU = $CPU; NewlyDeferred = $false; TestMachine = $true}
                        }
                    }
                }
            }

            $CustomPSObjectComputerMap = $NewComputerMap | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }
            $UnsignedStagedPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\{$($PolicyInfo.PolicyGUID)}.cip")
            $SignedStagedPolicyPath = $null
            ConvertFrom-CIPolicy -BinaryFilePath $UnsignedStagedPolicyPath -XmlFilePath $PolicyPath -ErrorAction Stop | Out-Null
            $Test = $false
            if (($CustomPSObjectComputerMap | Where-Object {$_.TestMachine -eq $true} | Select-Object DeviceName).Count -ge 1) {
                $Test = $true
            }

            $results = $null
            $Machines = $null

            if ($Test) {
                $Machines = ($CustomPSObjectComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($_.TestMachine -eq $true) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
            } else {
                $Machines = ($CustomPSObjectComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
            }

            #Copy WDAC Policies and Refresh Tools
            ##======================================================================================
            if ($SignedToUnsigned) {

                #Get Signed First

                #Copy to Machine(s)

                #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed

                #Increment Version Number

                #Get Unsigned Second

                #Copy to Machine(s)

                #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed

            } else {

                if ($PolicyInfo.IsSigned -eq $true) {
                    #Get Signed

                    #Copy to Machine(s)

                    #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed

                } else {
                    #Copy to Machine(s)
                    Copy-StagedWDACPolicies -CIPolicyPath $UnsignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -Test:($Test -and ($TestComputers.Count -ge 1)) -SkipSetup:$SkipSetup

                    #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed
                    $results = Invoke-ActivateAndRefreshWDACPolicy -Machines $Machines -CIPolicyFileName (Split-Path $UnsignedStagedPolicyPath -Leaf) -X86_RefreshToolName (Split-Path $X86_Path -Leaf) -AMD64_RefreshToolName (Split-Path $AMD64_Path -Leaf) -ARM64_RefreshToolName (Split-Path $ARM64_Path -Leaf) -RemoteStagingDirectory $RemoteStagingDirectory -ErrorAction Stop

                }
            }
            ##======================================================================================

            if ($CustomPSObjectComputerMap) {
            #Assign devices as deferred in the database which have failed to apply the new WDAC policy




            }

            Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            $Transaction.Commit()
            $Connection.Close()
        }
        
    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List -Property * | Out-String)
        throw $theError
    }
}

function Restore-WDACWorkstations {
    <#
    .SYNOPSIS
    For computers which were initially not part of a group of test computers -- or for computers which were not remotely available or couldn't
    apply the most recent policy version -- bring them up to date with the the policy specified.

    .DESCRIPTION
    This cmdlet will remove workstations / PCs from "deferred" status if it can successfully deploy the newest policy designated by PolicyGUID to the applicable workstations.
    If the "WorkstatioNName" parameter does not specify a workstation, then all devices with a deferred status and associated with a policy.
    Many of the same elements of deploying policies is borrowed from the Deploy-Policies cmdlet.

    Author: Nathan Jepson
    License: MIT License

    .PARAMETER PolicyGUID
    ID of the policy (NOT the alternate ID which WDAC policies also have, although you can use the alias "PolicyID" for this parameter)

    .PARAMETER PolicyName
    Name of the policy (exact)

    .PARAMETER WorkstationName
    Specify this parameter if you only want to restore particular workstations to the current WDAC policy.

    .EXAMPLE
    TODO

    .EXAMPLE
    TODO

    #>
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Alias("PolicyID","id")]
        [string]$PolicyGUID,
        [ValidateNotNullOrEmpty()]
        [string]$PolicyName,
        [ValidateNotNullOrEmpty()]
        [Alias("Workstations","Workstation","Device","Devices","PC","Computer","Computers")]
        [string[]]$WorkstationName
    )

    if ($PolicyName -and $PolicyGUID) {
        throw "Cannot provide both a policy name and policy GUID."
    }

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        
        if ($PolicyName) {
            $PolicyInfo = Get-WDACPolicyByName -PolicyName $PolicyName -Connection $Connection
            $PolicyGUID = $PolicyInfo.PolicyGUID
        } elseif ($PolicyGUID) {
            $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection
        }
    
        #Deferred flag is set here, unlike the above cmdlet
        $ComputerMapTemp = Get-WDACDevicesNeedingWDACPolicy -PolicyGUID $PolicyGUID -Deferred -Connection $Connection -ErrorAction Stop
        $ComputerMap = @{}
        if ($WorkstationName) {
            foreach ($Entry in $ComputerMapTemp.GetEnumerator()) {
                if ($WorkstationName -contains $Entry.Name) {
                    $ComputerMap += @{$Entry.Name = $Entry.Value}
                }
            }
        }
    } catch {
        $theError = $_
        Write-Verbose ($theError | Format-List -Property * | Out-String)
        throw $theError
    }
}