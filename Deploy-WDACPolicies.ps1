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

function Get-YesOrNoPrompt {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Prompt
    )

    Write-Host ($Prompt + " (Y/N): ") -NoNewline
    while ($true) {
        $InputString = Read-Host
        if ($InputString.ToLower() -eq "y") {
            return $true
        } elseif ($InputString.ToLower() -eq "n") {
            return $false
        } else {
            Write-Host "Not a valid option. Please supply y or n."
        }
    }
}

function Set-MachineDeferred {
    [cmdletbinding()]
    Param ( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not (Set-WDACDeviceDeferredStatus -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop)) {
        throw "Unable to update deferred status for $DeviceName"
    }

    if (-not (Test-PolicyDeferredOnDevice -PolicyGUID $PolicyGUID -WorkstationName $DeviceName -Connection $Connection -ErrorAction Stop)) {
        $PolicyVersion = Get-WDACPolicyLastDeployedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        $DeferredPolicy = $null
        if (Test-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $PolicyVersion -Connection $Connection -ErrorAction Stop) {
            $DeferredPolicy = Get-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
        } else {
            if (-not (Add-DeferredWDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                throw "Cannot add deferred WDAC policy of GUID $PolicyGUID and version $PolicyVersion"
            }
            $DeferredPolicy = Get-DeferredWDACPolicy -DeferredDevicePolicyGUID $PolicyGUID -PolicyVersion $PolicyVersion -Connection $Connection -ErrorAction Stop
        }

        if (-not (Add-DeferredWDACPolicyAssignment -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -DeviceName $DeviceName -Comment $Comment -Connection $Connection -ErrorAction Stop)) {
            throw "Unable to add deferred policy assignment of deferred policy index $($DeferredPolicy.DeferredPolicyIndex) to device $DeviceName"
        }
    }
}

function Remove-MachineDeferred {
    [cmdletbinding()]
    Param ( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyGUID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    #TODO
}

function Deploy-WDACPolicies {
    <#
    .SYNOPSIS
    This function deploys WDAC policies specified by parameter input -- 
    ONLY IF the latest version hasn't yet been deployed -- signs them (if applicable)
    and copies them to the relevant machines which have those policies assigned.
    Then a RefreshPolicy action is enacted on that machine.

    .DESCRIPTION
    This function determines what machines have the designated policy assigned to them, by checking group assignments, ad-hoc assignments,
    and the policy "pillar" attribute. (A policy set as a pillar is deployed to every device listed in the trust database.)
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
    deployed on a device for the first time or when you are modifying a policy that is signed to be unsigned.

    .PARAMETER SleepTime
    This is how long to wait for before continuing script execution after a restart job is performed to remove boot-protection for signed
    WDAC policies -- this ONLY applies when a previously signed policy becomes unsigned.

    .EXAMPLE
    Deploy-WDACPolicies -PolicyGUID "4ac96917-6f84-43c3-ab68-e9a7bc87eb8f"

    .EXAMPLE
    Deploy-WDACPolicies -PolicyGUID "4ac96917-6f84-43c3-ab68-e9a7bc87eb8f" -TestComputers PC1,PC2

    .EXAMPLE
    Deploy-WDACPolicies -PolicyGUID "4ac96917-6f84-43c3-ab68-e9a7bc87eb8f" -TestComputers PC1,StandoutPC -TestForce -SkipSetup -ForceRestart
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
        [switch]$ForceRestart,
        [int]$SleepTime=480
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

    if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
        $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
        Write-Verbose "The current file is in the SignedModules folder."
    } else {
        $PSModuleRoot = $PSScriptRoot
    }

    $Connection = $null
    $Transaction = $null
    $SignedStagedPolicyPath = $null
    $UnsignedStagedPolicyPath = $null

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        $Transaction = $Connection.BeginTransaction()
        
        if ($PolicyName) {
            $PolicyInfo = Get-WDACPolicyByName -PolicyName $PolicyName -Connection $Connection -ErrorAction Stop
            $PolicyGUID = $PolicyInfo.PolicyGUID
        } elseif ($PolicyGUID) {
            $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        }

        $SignedToUnsigned = Test-MustRemoveSignedPolicy -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        if ( ($PolicyInfo.IsSigned -eq $true) -or $SignedToUnsigned) {
        #Check if all local variables are correctly set to be able to sign and deploy WDAC policies
            $WDACodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
            if (-not $WDACodeSigningCert -or "" -eq $WDACodeSigningCert) {
                throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
            } elseif (-not ($WDACodeSigningCert.ToLower() -match "cert\:\\")) {
                throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
            }
            
            #See if it's in the Local Cert Store
            $cert = Get-ChildItem -Path $WDACodeSigningCert -ErrorAction Stop
            
            $SignTool = (Get-LocalStorageJSON -ErrorAction Stop)."SignTool"
            if (-not $SignTool -or ("" -eq $SignTool) -or ("Full_Path_To_SignTool.exe" -eq $SignTool)) {
                throw "Error: Empty, default, or null value for WDAC Policy signing certificate retreived from Local Storage."
            } elseif (-not (Test-Path $SignTool)) {
                throw "Path for Sign tool does not exist or not a valid path."
            }

            if (-not ($cert.Subject -match "(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))")) {
                throw "WDACCodeSigningCert subject name not in the correct format. Example: CN=WDACSigningCertificate "
            }
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
            $X86_Path = $null
            $AMD64_Path = $null
            $ARM64_Path = $null

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

            if ($X86_Path) {
                $X86_RefreshToolName = Split-Path $X86_Path -Leaf
            }
            if ($AMD64_Path) {
                $AMD64_RefreshToolName = Split-Path $AMD64_Path -Leaf
            }
            if ($ARM64_Path) {
                $ARM64_RefreshToolName = Split-Path $ARM64_Path -Leaf
            }
            $CustomPSObjectComputerMap = $NewComputerMap | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }
            $UnsignedStagedPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\{$($PolicyInfo.PolicyGUID)}.cip")
            if (Test-Path $UnsignedStagedPolicyPath) {
                Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction Stop
            }
            $SignedStagedPolicyPath = $null
            ConvertFrom-CIPolicy -BinaryFilePath $UnsignedStagedPolicyPath -XmlFilePath $PolicyPath -ErrorAction Stop | Out-Null

            ##Check if Restart is Required on Devices. If there is a mix of statuses, then defer the ones which haven't been deployed yet and set $RestartRequired to $false.
            $RestartRequired = $false
            if ($PolicyInfo.IsSigned -eq $true -and (-not ($PolicyInfo.BaseOrSupplemental -eq $true))) {
            #A policy does not necessitate a restart if it's a supplemental policy

                $RestartRequired = $true
                foreach ($ComputerInfo in $CustomPSObjectComputerMap) {
                    $Name = $ComputerInfo.DeviceName
                    if (Test-FirstSignedPolicyDeployment -PolicyGUID $PolicyGUID -DeviceName $Name -Connection $Connection -ErrorAction Stop) {
                        $RestartRequired = $false
                    }
                }

                if (-not $RestartRequired) {
                #Go through each device and if they have never received a deployment yet, then defer them (since other devices already were restarted)
                    for ($i=0; $i -lt $CustomPSObjectComputerMap.Count; $i++) {
                        if (-not (Test-FirstSignedPolicyDeployment -PolicyGUID $PolicyGUID -DeviceName ($CustomPSObjectComputerMap[$i].DeviceName) -Connection $Connection -ErrorAction Stop)) {
                            $CustomPSObjectComputerMap[$i].NewlyDeferred = $true
                            Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName ($CustomPSObjectComputerMap[$i].DeviceName) -Comment "Machine has not yet received first signed deployment while other machines have." -Connection $Connection -ErrorAction Stop
                        }
                    }
                }
            }
            ##############################################################################################################################

            $Machines = $null
            $results = $null
            $Test = $false
            if (($CustomPSObjectComputerMap | Where-Object {$_.TestMachine -eq $true} | Select-Object DeviceName).Count -ge 1) {
                $Test = $true
            }
            if ($Test) {
                $Machines = ($CustomPSObjectComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($_.TestMachine -eq $true) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
            } else {
                $Machines = ($CustomPSObjectComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
            }

            $SuccessfulMachines = @()
            #This list is only used when SignedToUnsigned is set to true

            #Copy WDAC Policies and Refresh Tools
            ##======================================================================================
            if ($SignedToUnsigned) {
                if (-not (Get-YesOrNoPrompt -Prompt "Devices will require a restart to fully remove UEFI boot protection of old, signed policy. Continue with script execution?")) {
                    $Transaction.Rollback()
                    $Connection.Close()
                    return
                }

                #Get Signed First
                $SignedStagedPolicyPath = Invoke-SignTool -CIPPolicyPath $UnsignedStagedPolicyPath -DestinationDirectory (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -ErrorAction Stop
                Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction Stop
                Rename-Item -Path $SignedStagedPolicyPath -NewName (Split-Path $UnsignedStagedPolicyPath -Leaf) -Force -ErrorAction Stop
                $SignedStagedPolicyPath = $UnsignedStagedPolicyPath

                #Copy to Machine(s)
                Copy-StagedWDACPolicies -CIPolicyPath $SignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -Test:($Test -and ($TestComputers.Count -ge 1)) -SkipSetup:$SkipSetup

                #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed
                #NOTE: The "restartrequired" flag is not used here because that would prevent the refresh tool from being used
                #...Instead, devices will simply be restarted below after the first initial transaction commit
                $results = Invoke-ActivateAndRefreshWDACPolicy -Machines $Machines -CIPolicyFileName (Split-Path $SignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -Signed -ErrorAction Stop
                
                $results | ForEach-Object {
                    if ($_.RefreshCompletedSuccessfully -eq $true) {
                        $SuccessfulMachines += $_.PSComputerName
                    } else {
                        Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Comment ("Unable to deploy initial signed policy before deploying unsigned policy." + $_.ResultMessage) -Connection $Connection -ErrorAction Stop
                    }
                }

                #Set most recently deployed version in Database
                try {
                    if (-not (Set-WDACPolicyLastDeployedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to set LastDeployedPolicyVersion to match the temporary signed one just deployed."
                    }
                } catch {
                    Write-Verbose ($_ | Format-List -Property * | Out-String)
                    throw "Unable to set the LastDeployedPolicyVersion to be equal to the temporary signed PolicyVersion: $($PolicyInfo.PolicyVersion) ."
                }

                #Increment Version Number
                New-WDACPolicyVersionIncrementOne -PolicyGUID $PolicyGUID -CurrentVersion $PolicyInfo.PolicyVersion -Connection $Connection -ErrorAction Stop                

                #Set deferred those devices which were not initially deployed with temporary signed policy
                for ($i=0; $i -lt $CustomPSObjectComputerMap.Count; $i++) {
                    if (-not ($SuccessfulMachines -contains $CustomPSObjectComputerMap[$i].DeviceName)) {
                        $CustomPSObjectComputerMap[$i].NewlyDeferred = $true
                    } elseif ($CustomPSObjectComputerMap[$i].NewlyDeferred -eq $true) {
                        Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $CustomPSObjectComputerMap[$i].DeviceName -Comment "Pre-script checks for device not satisfied or device not a test machine." -Connection $Connection -ErrorAction Stop
                    }
                }

                #Set this temporary signed version number as the most recent signed version
                try {
                    if (-not (Set-WDACPolicyLastSignedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                        throw "Unable to set LastSignedVersion to match the temporary signed one just deployed."
                    }
                } catch {
                    Write-Verbose ($_ | Format-List -Property * | Out-String)
                    throw "Unable to set the LastSignedVersion to be equal to the temporary signed PolicyVersion: $($PolicyInfo.PolicyVersion) ."
                }

                $Transaction.Commit()
                $Transaction = $Connection.BeginTransaction()

                #Restart Machines to Remove UEFI boot protection on Signed Policy 
                if (($SuccessfulMachines.Count -ge 1)) {

                    if ($ForceRestart) {
                        Restart-WDACDevices -Devices $SuccessfulMachines
                    } else {
                        $DevicesWithComma = $SuccessfulMachines -join ","
                        if (Get-YesOrNoPrompt -Prompt "Some devices will require a restart to fully remove UEFI boot protection of old, signed policy. Restart these devices now? Users will lose unsaved work: $DevicesWithComma `n") {
                            Restart-WDACDevices -Devices $SuccessfulMachines
                        } else {
                            #There's got to be a better way of doing this
                            while (-not (Get-YesOrNoPrompt -Prompt "This script cannot continue execution until devices can be restarted. `n Device might blue-screen if you do not restart them. To restart, select `"Y`"")) {
                                continue
                            }
                            Restart-WDACDevices -Devices $SuccessfulMachines
                        }
                    }
                }

                #Wait for machines to boot back up, default 8 minutes
                Start-Sleep -Seconds $SleepTime

                #Get Unsigned Second
                $PolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
                ConvertFrom-CIPolicy -BinaryFilePath $UnsignedStagedPolicyPath -XmlFilePath $PolicyPath -ErrorAction Stop | Out-Null

                #Copy to Machine(s)
                Copy-StagedWDACPolicies -CIPolicyPath $UnsignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -Test:($Test -and ($TestComputers.Count -ge 1)) -SkipSetup:$SkipSetup

                #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed
                $results = Invoke-ActivateAndRefreshWDACPolicy -Machines $SuccessfulMachines -CIPolicyFileName (Split-Path $UnsignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -RemoveUEFI -ErrorAction Stop

                #If there are no results, or null is returned, then no WinRM session was successful
                if (-not $results) {
                    for ($i=0; $i -lt $CustomPSObjectComputerMap.Count; $i++) {
                        $CustomPSObjectComputerMap[$i].NewlyDeferred = $true
                        Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $CustomPSObjectComputerMap[$i].DeviceName -Comment "Unable to establish WinRM connection to machine to apply unsigned policy to machine after deploying temporary signed policy." -Connection $Connection -ErrorAction Stop
                    }
                } else {
                #Remove all entries in "first_signed_policy_deployments" for this policy
                    if (-not (Remove-AllFirstSignedPolicyDeployments -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                        Write-Warning "Unable to remove all entries first_signed_policy_deployments for Policy $PolicyGUID . It is recommended to clear these entries out before next running this script."
                    }
                }

            } else {
                if ($PolicyInfo.IsSigned -eq $true) {
                    #Get Signed
                    $SignedStagedPolicyPath = Invoke-SignTool -CIPPolicyPath $UnsignedStagedPolicyPath -DestinationDirectory (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData") -ErrorAction Stop
                    Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction Stop
                    Rename-Item -Path $SignedStagedPolicyPath -NewName (Split-Path $UnsignedStagedPolicyPath -Leaf) -Force -ErrorAction Stop
                    $SignedStagedPolicyPath = $UnsignedStagedPolicyPath

                    #Copy to Machine(s)
                    Copy-StagedWDACPolicies -CIPolicyPath $SignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -Test:($Test -and ($TestComputers.Count -ge 1)) -SkipSetup:$SkipSetup

                    #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed
                    $results = Invoke-ActivateAndRefreshWDACPolicy -Machines $Machines -CIPolicyFileName (Split-Path $SignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -Signed -RestartRequired:$RestartRequired -ForceRestart:$ForceRestart -ErrorAction Stop

                } else {
                    #Copy to Machine(s)
                    Copy-StagedWDACPolicies -CIPolicyPath $UnsignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -Test:($Test -and ($TestComputers.Count -ge 1)) -SkipSetup:$SkipSetup

                    #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed
                    $results = Invoke-ActivateAndRefreshWDACPolicy -Machines $Machines -CIPolicyFileName (Split-Path $UnsignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -ErrorAction Stop

                }
            }
            ##======================================================================================

            $DevicesToRestart = @()
            if ($CustomPSObjectComputerMap -and $results) {
            #Assign devices as deferred in the database which have failed to apply the new WDAC policy
            #......If it is a first signed deployment, then restart devices and add relevant "first_signed_policy_deployment" entries (only for successes)

                if ($VerbosePreference) {
                    $results | Select-Object PSComputerName,ResultMessage,WinRMSuccess,RefreshToolAndPolicyPresent,CopyToCIPoliciesActiveSuccessfull,CopyToEFIMount,RefreshCompletedSuccessfully,ReadyForARestart | Format-List -Property *
                }

                $results | ForEach-Object {
                    if ($SignedToUnsigned) {
                        if (-not ($SuccessfulMachines -contains $_.PSComputerName)) {
                            Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Comment "Device did not deploy initial signed policy successfully before subsequent unsigned policy." -Connection $Connection -ErrorAction Stop
                        }
                    } elseif ($null -eq $_.ResultMessage) {
                        #Defer
                        Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Comment "No initial WinRM sessions established with device." -Connection $Connection -ErrorAction Stop
                    } elseif ($RestartRequired) {
                        if ($_.ReadyForARestart -eq $true) {
                            $DevicesToRestart += $_.PSComputerName

                        } else {
                            #Defer
                            Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Comment $_.ResultMessage -Connection $Connection -ErrorAction Stop
                        }
                    } else {
                        if (-not ($_.RefreshCompletedSuccessfully -eq $true)) {
                            #Defer
                            Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Comment $_.ResultMessage -Connection $Connection -ErrorAction Stop
                        }
                    }
                }

                $RemoteFailures = @()

                ##Set All other Deferred Policies and Deferred Policy Assignments##
                for ($i=0; $i -lt $CustomPSObjectComputerMap.Count; $i++) {
                    if ($CustomPSObjectComputerMap[$i].NewlyDeferred -eq $true) {
                        Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $CustomPSObjectComputerMap[$i].DeviceName -Comment "Pre script check failures or pre-signed-deployment check not satisfied or is not a test machine." -Connection $Connection -ErrorAction Stop
                        continue
                    }
                    
                    $MachineNotPresent = $true
                    foreach ($Computer in $results) {
                        if ( ($CustomPSObjectComputerMap[$i].DeviceName) -eq $Computer.PSComputerName) {
                            $MachineNotPresent = $false
                        }
                    }

                    if ($MachineNotPresent) {
                        Set-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $CustomPSObjectComputerMap[$i].DeviceName -Comment "PowerShell Remoting (WinRM) failed on this device." -Connection $Connection -ErrorAction Stop
                        $RemoteFailures += ($CustomPSObjectComputerMap[$i].DeviceName)
                    }
                }
                ###################################################################

                if ($RemoteFailures.Count -ge 1) {
                    Write-Warning ("Powershell remoting (WinRM) failed on these devices: " + ($RemoteFailures -join ","))
                }

                ## Restart Devices ################################################
                if ($RestartRequired -and ($DevicesToRestart.Count -ge 1) -and (-not $SignedToUnsigned)) {

                    if ($ForceRestart) {
                        Restart-WDACDevices -Devices $DevicesToRestart
                    } else {
                        $DevicesWithComma = $DevicesToRestart -join ","
                        if (Get-YesOrNoPrompt -Prompt "Some devices will require a restart to fully deploy the signed policy. Restart these devices now? Users will lose unsaved work: $DevicesWithComma `n") {
                            Restart-WDACDevices -Devices $DevicesToRestart
                        } else {
                            Write-Host "Please restart devices soon so that the new signed policy can take effect."
                        }
                    }

                    foreach ($Device in $DevicesToRestart) {
                        try {
                            if (-not (Add-FirstSignedPolicyDeployment -PolicyGUID $PolicyGUID -DeviceName $Device -Connection $Connection -ErrorAction Stop)) {
                                throw "Unable to add first_signed_policy_deployment entry for device $Device ."
                            }
                        } catch {
                            Write-Verbose ($_ | Format-List -Property * | Out-String)
                            Write-Warning "Unable to add first_signed_policy_deployment entry for device $Device ."
                        }
                    }
                }
                ###################################################################

            } elseif (-not $results) {
                if ($SignedToUnsigned) {
                    $Transaction.Commit()
                } else {
                    $Transaction.Rollback()
                }
                $Connection.Close()
                throw "No remote powershell results from attempting to refresh policies -- for all devices."
            }

            #Write policy info to the database, LastDeployedPolicyVersion
            try {
                if (-not (Set-WDACPolicyLastDeployedVersion -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop)) {
                    throw "Unable to set LastDeployedPolicyVersion to match the one just deployed."
                }
            } catch {
                Write-Verbose ($_ | Format-List -Property * | Out-String)
                Write-Warning "Unable to set the LastDeployedPolicyVersion to be equal to the PolicyVersion: $($PolicyInfo.PolicyVersion) . Please set this value in the trust database."
            }

            $Transaction.Commit()
            $Connection.Close()

            Write-Host "Policy has been deployed."

            if ($SignedStagedPolicyPath) {
                if (Test-Path $SignedStagedPolicyPath -ErrorAction SilentlyContinue) {
                    Remove-Item -Path $SignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
                }
            }
            if ($UnsignedStagedPolicyPath) {
                if (Test-Path $UnsignedStagedPolicyPath -ErrorAction SilentlyContinue) {
                    Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
    } catch {
        $theError = $_

        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }
        if ($SignedStagedPolicyPath) {
            if (Test-Path $SignedStagedPolicyPath) {
                Remove-Item -Path $SignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
        if ($UnsignedStagedPolicyPath) {
            if (Test-Path $UnsignedStagedPolicyPath) {
                Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
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

    .PARAMETER SkipSetup
    Cmdlet will not check whether staging directory or refresh tools are present on a device.

    .PARAMETER ForceRestart
    WARNING: Disruptive action.
    All devices* will be forced to restart! -- *Only applies to when a signed base policy is 
    deployed on a device for the first time or when you are modifying a policy that is signed to be unsigned.

    .PARAMETER SleepTime
    This is how long to wait for before continuing script execution after a restart job is performed to remove boot-protection for signed
    WDAC policies -- this ONLY applies when a previously signed policy becomes unsigned.

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
        [string[]]$WorkstationName,
        [switch]$SkipSetup,
        [switch]$ForceRestart,
        [int]$SleepTime=480
    )

    if ($PolicyName -and $PolicyGUID) {
        throw "Cannot provide both a policy name and policy GUID."
    }

    $Connection = $null
    $Transaction = $null
    $SignedStagedPolicyPath = $null
    $UnsignedStagedPolicyPath = $null
    $WDACodeSigningCert = $null
    $SignTool = $null
    $AMD64_Path = $null
    $ARM64_Path = $null
    $X86_Path = $null

    try {
        $Connection = New-SQLiteConnection -ErrorAction Stop
        
        if ($PolicyName) {
            $PolicyInfo = Get-WDACPolicyByName -PolicyName $PolicyName -Connection $Connection
            $PolicyGUID = $PolicyInfo.PolicyGUID
        } elseif ($PolicyGUID) {
            $PolicyInfo = Get-WDACPolicy -PolicyGUID $PolicyGUID -Connection $Connection
        }

        $RemoteStagingDirectory = (Get-LocalStorageJSON -ErrorAction Stop)."RemoteStagingDirectory"
        if (-not $RemoteStagingDirectory -or ("" -eq $RemoteStagingDirectory)) {
            throw "When deploying staged policies to remote machines, you must designate a RemoteStagingDirectory in LocalStorage.json."
        }

        try {
            Split-Path $RemoteStagingDirectory -Qualifier -ErrorAction Stop | Out-Null
        } catch {
            throw "The RemoteStagingDirectory must have a qualifier such as `"C:\`" or `"D:\`" at the beginning."
        }

        if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
            $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
            Write-Verbose "The current file is in the SignedModules folder."
        } else {
            $PSModuleRoot = $PSScriptRoot
        }

        $UnsignedStagedPolicyPath = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\{$($PolicyInfo.PolicyGUID)}.cip")
        $SignedStagedPolicyPath = $null
        if (Test-Path $UnsignedStagedPolicyPath) {
            Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction Stop
        }
        $PolicyPath = Get-FullPolicyPath -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop
        ConvertFrom-CIPolicy -BinaryFilePath $UnsignedStagedPolicyPath -XmlFilePath $PolicyPath -ErrorAction Stop | Out-Null
    
        #Deferred flag is set here, unlike the above cmdlet
        if ($PolicyInfo.IsPillar -eq $true) {
            $ComputerMapTemp = Get-WDACDevicesAllNamesAndCPUInfo -Deferred -Connection $Connection -ErrorAction Stop
        } else {
            $ComputerMapTemp = Get-WDACDevicesNeedingWDACPolicy -PolicyGUID $PolicyGUID -Deferred -Connection $Connection -ErrorAction Stop
        }

        $ComputerMap = @{}
        if ($WorkstationName) {
            foreach ($Entry in $ComputerMapTemp.GetEnumerator()) {
                $Name = $Entry.Name
                $Value = $Entry.Value
                if ($WorkstationName -contains $Name) {
                    if (Test-PolicyDeferredOnDevice -WorkstationName $Name -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) {
                        $ComputerMap += @{$Name = $Value}
                    }
                }
            }
        } else {
            foreach ($Entry in $ComputerMapTemp.GetEnumerator()) {
                $Name = $Entry.Name
                $Value = $Entry.Value
                if (Test-PolicyDeferredOnDevice -WorkstationName $Name -PolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop) {
                    $ComputerMap += @{$Name = $Value}
                }
            }
        }

        if ( (($null -eq $ComputerMap) -or $ComputerMap.Count -le 0)) {
            throw "No deferred workstations currently assigned to policy $PolicyGUID"
        }

        $AllDeferred = Get-DeferredWDACPolicies -DeferredDevicePolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

        foreach ($DeferredPolicy in $AllDeferred) {
            $results = $null
            $restartNeededResults = $null
            $restartNotNeededResults = $null
            $NewComputerMap = @{}
            $Transaction = $Connection.BeginTransaction()
            if ($DeferredPolicy.PolicyVersion) {
                Write-Verbose "Handling devices with old policy version $($DeferredPolicy.PolicyVersion)"
            } elseif ($DeferredPolicy.DeferredPolicyIndex) {
                Write-Verbose "Handling devices with deferred policy index $($DeferredPolicy.DeferredPolicyIndex)"
            }

            if ($null -ne $DeferredPolicy.PolicyVersion) {
                $CompareVersionsVariable = Compare-Versions -Version1 $PolicyInfo.PolicyVersion -Version2 $DeferredPolicy.PolicyVersion

                if (($CompareVersionsVariable -eq 0) -or ($CompareVersionsVariable -eq 1)) {
                #Deferred policy versions should always be less than the current version number. (Otherwise, this if statement executes.)
                    $Transaction.Rollback()
                    $Connection.Close()
                    if ($SignedStagedPolicyPath) {
                        if (Test-Path $SignedStagedPolicyPath) {
                            Remove-Item -Path $SignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    if ($UnsignedStagedPolicyPath) {
                        if (Test-Path $UnsignedStagedPolicyPath) {
                            Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    throw "Deferred policy version greater than or equal to the current version number of policy $PolicyGUID"
                }
            }

            if (($PolicyInfo.IsSigned -eq $true) -or (($DeferredPolicy.IsSigned -eq $true) -and ($PolicyInfo.IsSigned -eq $false))) {
                if (($null -eq $WDACodeSigningCert) -and ($null -eq $SignTool)) {
                    #Check if all local variables are correctly set to be able to sign and deploy WDAC policies
                    $WDACodeSigningCert = (Get-LocalStorageJSON -ErrorAction Stop)."WDACPolicySigningCertificate"
                    if (-not $WDACodeSigningCert -or "" -eq $WDACodeSigningCert) {
                        throw "Error: Empty or null value for WDAC Policy signing certificate retreived from Local Storage."
                    } elseif (-not ($WDACodeSigningCert.ToLower() -match "cert\:\\")) {
                        throw "Local cache does not specify a valid certificate path for the WDAC policy signing certificate. Please use a valid path. Example of a valid certificate path: `"Cert:\\CurrentUser\\My\\005A924AA26ABD88F84D6795CCC0AB09A6CE88E3`""
                    }
                    
                    #See if it's in the Local Cert Store
                    $cert = Get-ChildItem -Path $WDACodeSigningCert -ErrorAction Stop
                    
                    $SignTool = (Get-LocalStorageJSON -ErrorAction Stop)."SignTool"
                    if (-not $SignTool -or ("" -eq $SignTool) -or ("Full_Path_To_SignTool.exe" -eq $SignTool)) {
                        throw "Error: Empty, default, or null value for WDAC Policy signing certificate retreived from Local Storage."
                    } elseif (-not (Test-Path $SignTool)) {
                        throw "Path for Sign tool does not exist or not a valid path."
                    }

                    if (-not ($cert.Subject -match "(?<=CN=)(.*?)($|(?=,\s?[^\s,]+=))")) {
                        throw "WDACCodeSigningCert subject name not in the correct format. Example: CN=WDACSigningCertificate "
                    }
                }
            }

            foreach ($Computer in $ComputerMap.GetEnumerator()) {
                $thisComputer = $Computer.Name
                $CPU = $Computer.Value

                if (-not (Test-SpecificDeferredPolicyOnDevice -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -WorkstationName $Name -Connection $Connection -ErrorAction Stop)) {
                    continue
                }

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

                $NewComputerMap += @{DeviceName = $thisComputer; CPU = $CPU; NewlyDeferred = $false; TestMachine = $false}
            }

            if ($X86_Path) {
                $X86_RefreshToolName = Split-Path $X86_Path -Leaf
            }
            if ($AMD64_Path) {
                $AMD64_RefreshToolName = Split-Path $AMD64_Path -Leaf
            }
            if ($ARM64_Path) {
                $ARM64_RefreshToolName = Split-Path $ARM64_Path -Leaf
            }

            $CustomPSObjectComputerMap = $NewComputerMap | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }

            $MachinesNeedingRestart = @()
            $MachinesNotNeedingRestart = @()
            $Machines = ($CustomPSObjectComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
            $SignedToUnsigned = $false

            if (($DeferredPolicy.IsSigned -eq $true) -and ($PolicyInfo.IsSigned -eq $false)) {
                $SignedToUnsigned = $true
            }

            foreach ($Machine in $Machines) {
                if (($DeferredPolicy.IsSigned -eq $true) -and (-not (Test-FirstSignedPolicyDeployment -PolicyGUID $PolicyGUID -DeviceName $Machine -Connection $Connection -ErrorAction Stop))) {
                    $MachinesNeedingRestart += $Machine
                } else {
                    $MachinesNotNeedingRestart += $Machine
                }
            }

            if (($null -eq $Machines) -or ($Machines.Count -le 0)) {
                $Transaction.Commit()
                continue
            }

            if ($SignedToUnsigned) {
                if (-not (Get-YesOrNoPrompt -Prompt "Some devices will require a restart to fully remove UEFI boot protection of old, signed policy. Continue with script execution?")) {
                    $Transaction.Commit()
                    #Transaction is commit here because there were some CPU write actions above and not many other write actions
                    $Connection.Close()
                    if ($UnsignedStagedPolicyPath) {
                        if (Test-Path $UnsignedStagedPolicyPath) {
                            Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    if ($SignedStagedPolicyPath) {
                        if (Test-Path $SignedStagedPolicyPath) {
                            Remove-Item -Path $SignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    return
                }

                #TODO
                throw "FIXME: Fixing signed deferred policies for currently signed policies will soon be implemented, but is not currently implemented"

            } else {

                if ($PolicyInfo.IsSigned -eq $true) {
                    #Get Signed
                    if ($null -eq $SignedStagedPolicyPath) {
                        $SignedPolicyDir = (Join-Path -Path $PSModuleRoot -ChildPath ".\.WDACFrameworkData\Signed")
                        $SignedStagedPolicyPath = Invoke-SignTool -CIPPolicyPath $UnsignedStagedPolicyPath -DestinationDirectory $SignedPolicyDir -ErrorAction Stop
                        Rename-Item -Path $SignedStagedPolicyPath -NewName (Split-Path $UnsignedStagedPolicyPath -Leaf) -Force -ErrorAction Stop
                        $SignedStagedPolicyPath = Join-Path ($SignedPolicyDir) -ChildPath (Split-Path $UnsignedStagedPolicyPath -Leaf)
                    }

                    #Copy to Machine(s)
                    Copy-StagedWDACPolicies -CIPolicyPath $SignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -FixDeferred -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -SkipSetup:$SkipSetup

                    #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed                
                    $restartNeededResults = Invoke-ActivateAndRefreshWDACPolicy -Machines $MachinesNeedingRestart -CIPolicyFileName (Split-Path $SignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -Signed -RestartRequired -ForceRestart:$ForceRestart -ErrorAction Stop
                    $restartNotNeededResults = Invoke-ActivateAndRefreshWDACPolicy -Machines $MachinesNotNeedingRestart -CIPolicyFileName (Split-Path $SignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -Signed -ErrorAction Stop

                    if ($VerbosePreference) {
                        $restartNeededResults | Select-Object PSComputerName,ResultMessage,WinRMSuccess,RefreshToolAndPolicyPresent,CopyToCIPoliciesActiveSuccessfull,CopyToEFIMount,RefreshCompletedSuccessfully,ReadyForARestart | Format-List -Property *
                        $restartNotNeededResults | Select-Object PSComputerName,ResultMessage,WinRMSuccess,RefreshToolAndPolicyPresent,CopyToCIPoliciesActiveSuccessfull,CopyToEFIMount,RefreshCompletedSuccessfully,ReadyForARestart | Format-List -Property *
                    }

                    $SuccessfulMachinesToRestart = @()

                    $restartNeededResults | ForEach-Object {
                        if (($_.WinRMSuccess -eq $true) -and ($_.ReadyForARestart -eq $true)) {
                            $SuccessfulMachinesToRestart += $_.PSComputerName
                            Remove-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Connection $Connection -ErrorAction Stop
                        }
                    }

                    if ($SuccessfulMachinesToRestart.Count -ge 1) {
                        if ($ForceRestart) {
                            Restart-WDACDevices -Devices $SuccessfulMachinesToRestart
                        } else {
                            $DevicesWithComma = $SuccessfulMachinesToRestart -join ","
                            if (Get-YesOrNoPrompt -Prompt "Some devices will require a restart to fully deploy the signed policy. Restart these devices now? Users will lose unsaved work: $DevicesWithComma `n") {
                                Restart-WDACDevices -Devices $SuccessfulMachinesToRestart
                            } else {
                                Write-Host "Please restart devices soon so that the new signed policy can take effect."
                            }
                        }

                        foreach ($FirstSignedMachine in $SuccessfulMachinesToRestart) {
                            try {
                                if (-not (Add-FirstSignedPolicyDeployment -PolicyGUID $PolicyGUID -DeviceName $FirstSignedMachine -Connection $Connection -ErrorAction Stop)) {
                                    throw "Unable to add first_signed_policy_deployment entry for device $FirstSignedMachine ."
                                }
                            } catch {
                                Write-Verbose ($_ | Format-List -Property * | Out-String)
                                Write-Warning "Unable to add first_signed_policy_deployment entry for device $FirstSignedMachine ."
                            }
                        }
                    }

                    $restartNotNeededResults | ForEach-Object {
                        if (($_.WinRMSuccess -eq $true) -and ($_.RefreshCompletedSuccessfully -eq $true)) {
                            Remove-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Connection $Connection -ErrorAction Stop
                        }
                    }

                } else {
                    #Copy to Machine(s)
                    Copy-StagedWDACPolicies -CIPolicyPath $UnsignedStagedPolicyPath -ComputerMap $CustomPSObjectComputerMap -FixDeferred -X86_Path $X86_Path -AMD64_Path $AMD64_Path -ARM64_Path $ARM64_Path -RemoteStagingDirectory $RemoteStagingDirectory -SkipSetup:$SkipSetup

                    #Copy to CiPolicies\Active and Use Refresh Tool and Set Policy as Deployed
                    $results = Invoke-ActivateAndRefreshWDACPolicy -Machines $Machines -CIPolicyFileName (Split-Path $UnsignedStagedPolicyPath -Leaf) -X86_RefreshToolName $X86_RefreshToolName -AMD64_RefreshToolName $AMD64_RefreshToolName -ARM64_RefreshToolName $ARM64_RefreshToolName -RemoteStagingDirectory $RemoteStagingDirectory -ErrorAction Stop

                    if ($VerbosePreference) {
                        $results | Select-Object PSComputerName,ResultMessage,WinRMSuccess,RefreshToolAndPolicyPresent,CopyToCIPoliciesActiveSuccessfull,CopyToEFIMount,RefreshCompletedSuccessfully,ReadyForARestart | Format-List -Property *
                    }

                    $results | ForEach-Object {
                        if (($_.WinRMSuccess -eq $true) -and ($_.RefreshCompletedSuccessfully -eq $true)) {
                            Remove-MachineDeferred -PolicyGUID $PolicyGUID -DeviceName $_.PSComputerName -Connection $Connection -ErrorAction Stop
                        }
                    }
                }
            }

            $Transaction.Commit()
            if ($results -or $restartNotNeededResults -or $restartNeededResults) {
                if ($DeferredPolicy.PolicyVersion) {
                    Write-Host "Deployed new policy to fix those workstations with old version: $($DeferredPolicy.PolicyVersion)"
                } elseif ($DeferredPolicy.DeferredPolicyIndex) {
                    Write-Host "Deployed new policy to fix those workstations with deferred policy index: $($DeferredPolicy.DeferredPolicyIndex)"
                }
            }
        }

        if ($Connection) {
            $Connection.Close()
        }
        if ($SignedStagedPolicyPath) {
            if (Test-Path $SignedStagedPolicyPath) {
                Remove-Item -Path $SignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
        if ($UnsignedStagedPolicyPath) {
            if (Test-Path $UnsignedStagedPolicyPath) {
                Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }

    } catch {
       $theError = $_

        if ($Transaction) {
            $Transaction.Rollback()
        }
        if ($Connection) {
            $Connection.Close()
        }
        if ($SignedStagedPolicyPath) {
            if (Test-Path $SignedStagedPolicyPath) {
                Remove-Item -Path $SignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
        if ($UnsignedStagedPolicyPath) {
            if (Test-Path $UnsignedStagedPolicyPath) {
                Remove-Item -Path $UnsignedStagedPolicyPath -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Verbose ($theError | Format-List -Property * | Out-String)
        throw $theError
    }
}