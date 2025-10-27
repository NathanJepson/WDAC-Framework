$ThisIsASignedModule = $false
if ((Split-Path (Get-Item $PSScriptRoot) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
    $ThisIsASignedModule = $true
} else {
    $PSModuleRoot = $PSScriptRoot
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools.psm1")
}

if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part3.psm1")) {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\SQL-TrustDBTools_Part3.psm1")
} else {
    Import-Module (Join-Path $PSModuleRoot -ChildPath "Resources\SQL-TrustDBTools_Part3.psm1")
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
        [string]$PolicyVersion,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )

    if (-not (Set-WDACDeviceDeferredStatus -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop)) {
        throw "Unable to update deferred status for $DeviceName"
    }

    if (-not (Test-PolicyDeferredOnDevice -PolicyGUID $PolicyGUID -WorkstationName $DeviceName -Connection $Connection -ErrorAction Stop)) {
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

    $DeferredPolicies = Get-DeferredWDACPolicies -DeferredDevicePolicyGUID $PolicyGUID -Connection $Connection -ErrorAction Stop

    foreach ($DeferredPolicy in $DeferredPolicies) {
        if (Test-SpecificDeferredPolicyOnDevice -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -WorkstationName $DeviceName -Connection $Connection -ErrorAction Stop) {
            if (-not (Remove-DeferredWDACPolicyAssignment -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -DeviceName $DeviceName -Connection $Connection -ErrorAction Stop)) {
                throw "Unsuccessful in removing deferred policy assignment of this policy on device $DeviceName : $($DeferredPolicy.DeferredPolicyIndex)"
            } else {
                if (-not (Test-AnyDeferredWDACPolicyAssignments -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -Connection $Connection -ErrorAction Stop)) {
                    if (-not (Remove-DeferredWDACPolicy -DeferredPolicyIndex $DeferredPolicy.DeferredPolicyIndex -Connection $Connection -ErrorAction Stop)) {
                        throw "Trouble removing deferred policy with index $($DeferredPolicy.DeferredPolicyIndex) after the removal of its last assignment."
                    }
                }
            }
        }
    }

    if (-not (Test-AnyPoliciesDeferredOnDevice -WorkstationName $DeviceName -Connection $Connection -ErrorAction Stop)) {
        if (-not (Set-WDACDeviceDeferredStatus -DeviceName $DeviceName -Unset -Connection $Connection -ErrorAction Stop)) {
            throw "Unable to reset deferred status on device $DeviceName back to normal. (This is the UpdateDeferring flag in the database)"
        }
    }
}

function Get-WDACDeployment {
    <#
    .SYNOPSIS
    For devices with the CiTool ONLY (e.g. Windows 11), get information on deployments
    for policy or policies (i.e., the latest version number of the policy), 
    and will then fix whether the device is deferred or without a first_signed_policy_deployment entry.
    
    .DESCRIPTION
    Uses CiTool on remote machine and turns result into a PSObject and returns.
    Upon returning, if a policy isn't in the database, that info is removed unless -verbose was specified.
    Based on the returned information, device deferment and first_Signed_policy_deployment flags will be fixed. (Unless
    -DoNotFix is specified, which has alias "PrintOnly.")
    If -AddDevices is specified, devices that aren't in the database are added to the database. It will ask what
    group you want to assign each PC to if -GroupName isn't specified.
    If -NoOutput isn't specified, the output is written to the screen, including which PCs failed WinRM.
    If -ReturnOutput is specified, it sends the result to the out pipeline (for example, if you want to put in a variable.)
    
    Author: Nathan Jepson
    License: MIT License

    .PARAMETER RemoteMachine
    The remote machine(s) to grab code integrity events from. Omit this parameter to grab events from just the local machine.

    .PARAMETER DoNotFix
    And alias "PrintOnly" -- When this parameter is supplied, only the policy information is printed,
    and the database is not updated (fixing deferred devices or first_signed_policy_deployment)

    .PARAMETER PolicyGUID
    Only probe for information regarding this specific policy.

    .PARAMETER PolicyName
    Only probe for information regarding this specific policy.

    .PARAMETER AddDevices
    Will add computers to database if they're not already present, 
    but it will ask what group you want to add it to, akin to Register-WDACWorkstation, 
    UNLESS a group name is provided.

    .PARAMETER GroupName
    When "AddDevices" and this parameter are supplied, a device will be added to that specific group,
    assuming it doesn't already exist in the database.

    .PARAMETER NoOutput
    Write no output to the console.

    .PARAMETER ReturnOutput
    Return results from devices as PSObject (for example, if you want to put everything into a variable).
    You can use with "NoOutput" if you don't want the output written to the screen before you return.
    Note that you will have to group the output by PCName yourself with: Group-Object -Property PSComputerName

    .PARAMETER Verbose
    Use verbose output to get all info on every policy on a remote device, including policies not contained
    in the database

    .EXAMPLE
    Get-WDACDeployment -RemoteMachine PC1 -PolicyName CASHIERS_POLICY -AddDevices -Verbose

    .EXAMPLE
    Get-WDACDeployment -RemoteMachines PC1,PC2 -PolicyGUID "cb859c93-a017-4b3f-97cc-f956a7e8673e" -PrintOnly

    .EXAMPLE
    Get-WDACDeployment -GroupName RetailDevices -AddDevices -NoOutput -Computer CheckoutPC1

    .EXAMPLE
    $PolicyDeployment = Get-WDACDeployment -RemoteMachines CheckoutPC1,CheckoutPC2 -DoNotFix -NoOutput -ReturnOutput -Verbose
    #>

    [CmdletBinding()]
    param(
        [Alias("Computer","Computers","PC","PCs","Machines","RemoteMachines")]
        [ValidateNotNullOrEmpty()]
        [string[]]$RemoteMachine,
        [Alias("PrintOnly")]
        [switch]$DoNotFix,
        [string]$PolicyGUID,
        [string]$PolicyName,
        [Alias("Add")]
        [switch]$AddDevices,
        [Alias("Group")]
        [string]$GroupName,
        [Alias("NoOut")]
        [switch]$NoOutput,
        [Alias("PipeOutput")]
        [switch]$ReturnOutput
    )

    $Connection = $null
    $Transaction = $null
    $WinRMErrors = $null

    try {        
        if ($ThisIsASignedModule) {
            Write-Verbose "The current file is in the SignedModules folder."
        }

        if ($PolicyGUID) {
            if (-not (Find-WDACPolicy -PolicyGUID $PolicyGUID -ErrorAction Stop)) {
                throw "No policy with GUID $PolicyGUID exists in the database."
            }
        } elseif ($PolicyName) {
            if (-not (Find-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop)) {
                throw "No policy with name $PolicyName exists."
            }
            $PolicyGUID = (Get-WDACPolicyByName -PolicyName $PolicyName -ErrorAction Stop).PolicyGUID
        }

        if ($GroupName -or $AddDevices) {
            $GroupNames = Get-WDACGroups -ErrorAction Stop
            if ($null -eq $GroupNames -or ($GroupNames.Count -le 0)) {
                throw "Create some groups before registering a new workstation."
            }
            $GroupNamesArray = @()
            for ($i=0; $i -lt $GroupNames.Count; $i++) {
                $GroupNamesArray += $GroupNames[$i].GroupName
            }

            if ($GroupName) {
                if (-not ($GroupNamesArray -contains $GroupName)) {
                    throw "$GroupName is not a valid group name and is not in the database."
                }
            }   
        }

        $results = $null
        $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction SilentlyContinue -ErrorVariable WinRMErrors
        if ($sess) {
            $results = $PolicyGUID,$VerbosePreference | Invoke-Command -Session $sess -ScriptBlock {
                $InputArray = @($input)
                $thisPolicyGUID = $InputArray[0]
                $isVerbose = $InputArray[1]

                if (-not (Test-Path "C:\Windows\System32\CiTool.exe")) {
                    $result = "Device does not have a CiTool."
                    $ResArray = @()
                    $ResArray += @{TheResult = $result}
                    $Data = $ResArray | ForEach-Object { New-Object -TypeName PSCustomObject | Add-Member -NotePropertyMembers $_ -PassThru }
                    return $Data
                } else {
                    if ($thisPolicyGUID) {
                        if ($isVerbose) {
                            $result = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object {$_.PolicyId -eq $thisPolicyGUID}
                        } else {
                            $result = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object {$_.PolicyId -eq $thisPolicyGUID} | Select-Object -Property PolicyID,FriendlyName,IsSignedPolicy,IsEnforced,VersionString
                        }
                        return $result
                    } else {
                        if ($isVerbose) {
                            $result = (CiTool -lp -json | ConvertFrom-Json).Policies
                        } else {
                            $result = (CiTool -lp -json | ConvertFrom-Json).Policies | Select-Object -Property PolicyID,FriendlyName,IsSignedPolicy,IsEnforced,VersionString
                        }
                        return $result
                    }
                }
            }

            $sess | Remove-PSSession -ErrorAction SilentlyContinue
        }

        if ($results) {
            $Connection = New-SQLiteConnection -ErrorAction Stop
            $Transaction = $Connection.BeginTransaction()
            $resultsDeepCopy = $null

            $PolicyInfo = Get-AllWDACPoliciesAndAllInfo -Connection $Connection -ErrorAction Stop
            $Policies = @()
            $LatestDeployed = @{}
            foreach ($Policy in $PolicyInfo) {
                $Policies += $Policy.PolicyGUID
                $LatestDeployed.Add($Policy.PolicyGUID,$Policy.LastDeployedPolicyVersion)
            }

            if ($VerbosePreference) {
                $resultsDeepCopy = $results
            }

            foreach ($result in $results) {
                if (-not ($result.TheResult)) {
                #If there was no failed result
                    if (-not ($Policies -contains $result.PolicyID)) {
                        $results = $results | Where-Object {$_ -ne $result}
                    }
                }
            }

            if (-not $DoNotFix) {
                $GroupNamesArray = @()
                $GroupNames = Get-WDACGroups -Connection $Connection -ErrorAction Stop
                for ($i=0; $i -lt $GroupNames.Count; $i++) {
                    $GroupNamesArray += $GroupNames[$i].GroupName
                }

                foreach ($result in $results) {
                    if ($result.TheResult) {
                    #This device had no CiTool
                        continue
                    }
                    $thisPCName = $result.PSComputerName
                    $thisVersion = $result.VersionString
                    $deployedVersion = $LatestDeployed[$result.PolicyID]
                    $PCInfo = Get-WDACDevice -DeviceName $thisPCName -Connection $Connection -ErrorAction Stop
                    $thisGroupName = $null
                    if (-not $PCInfo) {
                        if ($AddDevices) {
                            if ($GroupName) {
                                if (-not (Add-WDACDevice -DeviceName $thisPCName -AllowedGroup $GroupName -Connection $Connection -ErrorAction Stop)) {
                                    Write-Warning "Failed to add Device $thisPCName to the database."
                                }
                            } else {
                                Write-Host "What group name should workstation $thisPCName be assigned to?" -ForegroundColor Green
                                Write-Host ("Here are your options: " + ($GroupNamesArray -Join ","))  -ForegroundColor Yellow
                                $thisGroupName = Read-Host -Prompt "GroupName"

                                while (-not ($GroupNamesArray -contains $thisGroupName)) {
                                    Write-Host "Not a valid group name." -ForegroundColor Red
                                    Write-Host ("Here are your options: " + ($GroupNamesArray -Join ",")) -ForegroundColor Yellow
                                    $thisGroupName = Read-Host -Prompt "GroupName"
                                }

                                if (-not (Add-WDACDevice -DeviceName $thisPCName -AllowedGroup $thisGroupName -Connection $Connection -ErrorAction Stop)) {
                                    Write-Warning "Failed to add Device $thisPCName to the database."
                                }
                            }
                        } else {
                            #We can't put any other information for that device if it doesn't exist in the DB
                            continue
                        }
                    }

                    if (($result.IsSignedPolicy -eq $true) -and ($result.IsEnforced -eq $true)) {
                        if (-not (Test-FirstSignedPolicyDeployment -PolicyGUID ($result.PolicyID) -DeviceName $thisPCName -Connection $Connection -ErrorAction Stop)) {
                            if (-not (Add-FirstSignedPolicyDeployment -PolicyGUID ($result.PolicyID) -DeviceName $thisPCName -Connection $Connection -ErrorAction Stop)) {
                                Write-Warning "Unable to add first_signed_policy_deployment flag for device $thisPCName on policy $($result.PolicyID)"
                            }
                        }
                    }

                    $VersionCompare = Compare-Versions -Version1 $thisVersion -Version2 $deployedVersion

                    if ( (($VersionCompare -eq 1) -or ($VersionCompare -eq 0)) -and ($result.IsEnforced -eq $true)) {
                        Remove-MachineDeferred -PolicyGUID ($result.PolicyID) -DeviceName $thisPCName -Connection $Connection -ErrorAction Stop
                    } else {
                        Set-MachineDeferred -PolicyVersion $thisVersion -PolicyGUID ($result.PolicyID) -DeviceName $thisPCName -Comment "Device not on latest version as discovered by CiTool." -Connection $Connection -ErrorAction Stop
                    }
                }
            }

            $Transaction.Commit()
            $Connection.Close()

            if (-not $NoOutput) {
                if ($VerbosePreference) {
                    $results = $resultsDeepCopy
                    
                    if ($RemoteMachine.Count -ge 2) {
                        $results = $results | Group-Object -Property PSComputerName
                        foreach ($group in $results) {
                            Write-Host "Machine $($group.Name) :"
                            Write-Host ($group.Group | Format-List | Out-String)
                            
                        }
                    } else {
                        Write-Host ($results | Format-List | Out-String)
                    }
                } else {
                    if ($RemoteMachine.Count -ge 2) {
                        $results = $results | Select-Object PolicyID,FriendlyName,IsSignedPolicy,IsEnforced,VersionString,PSComputerName | Group-Object -Property PSComputerName
                        foreach ($group in $results) {
                            Write-Host "Machine $($group.Name) :"
                            Write-Host ($group.Group | Select-Object PolicyID,FriendlyName,IsSignedPolicy,IsEnforced,VersionString | Format-List | Out-String)
                            
                        }
                    } else {
                        $results | Select-Object PolicyID,FriendlyName,IsSignedPolicy,IsEnforced,VersionString,PSComputerName
                    }
                }
            }

            if ($ReturnOutput) {
                if ($VerbosePreference) {
                    return $resultsDeepCopy
                } else {
                    return $results
                }
            }
        } else {
            Write-Warning "No results."
        }

    } catch {
        if ($Transaction -and $Connection) {
            if ($Connection.AutoCommit -eq $false) {
                $Transaction.Rollback()
            }
        }
        if ($Connection) {
            $Connection.Close()
        }

        throw ($_ | Format-List | Out-string)

    } finally {
        if ($Transaction -and $Connection) {
            if ($Connection.AutoCommit -eq $false) {
                $Transaction.Rollback()
            }
        }
        if ($Connection) {
            $Connection.Close()
        }

        if (-not $NoOutput) {
            if ($WinRMErrors.Count -ge 1) {
                    Write-Host "`n"
                    Write-Host 'PowerShell Remoting (WinRM) failed on these devices:'
            }
            for ($i = 0; $i -lt $WinRMErrors.Count; $i++) {
                if ($WinRMErrors[$i].CategoryInfo.Reason -eq "PSRemotingTransportException") {
                    if ($WinRMErrors[$i].ErrorDetails.Message) {
                        $ErrorDevice = $WinRMErrors[$i].ErrorDetails.Message.Split("]")[0]
                        $ErrorDevice = $ErrorDevice.Substring(1)
                        Write-Host $ErrorDevice
                    }
                } else {
                    Write-Warning $WinRMErrors[$i]
                }
            }
        }
    }
}

Export-ModuleMember -Function Get-WDACDeployment