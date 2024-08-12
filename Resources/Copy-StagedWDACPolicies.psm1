if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\..\"
} else {
    $PSModuleRoot = Join-Path $PSScriptRoot -ChildPath "..\"
}

function Copy-StagedWDACPolicies {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $CIPolicyPath,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ComputerMap,
        $X86_Path = $null,
        $AMD64_Path = $null,
        $ARM64_Path = $null,
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        $RemoteStagingDirectory,
        [switch]$Test,
        [switch]$FixDeferred,
        [switch]$SkipSetup,
        [switch]$Signed
    )

    if (($null -eq $X86_Path) -and ($null -eq $AMD64_Path) -and ($null -eq $ARM64_Path)) {
        throw "No paths for refresh policy .exe tools provided to function."
    }

    if (Test-Path (Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Test-ValidWDACSignedPolicySignature.psm1")) {
        $TestValidWDACSignedPolicySignature_FilePath = Join-Path $PSModuleRoot -ChildPath "SignedModules\Resources\Test-ValidWDACSignedPolicySignature.psm1"
    } else {
        $TestValidWDACSignedPolicySignature_FilePath = (Join-Path $PSModuleRoot -ChildPath "Resources\Test-ValidWDACSignedPolicySignature.psm1")
    }
    
    if (-not $FixDeferred) {
        if ($Test) {
            $Machines = ($ComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($_.TestMachine -eq $true) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
        } else {
            $Machines = ($ComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
        }
    } else {
        $Machines = ($ComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
    }

    if ($Machines.Count -le 0) {
        throw "Unexpected: The usage of Copy-StagedWDACPolicies resulted in no devices receiving a WDAC policy file. This is likely the result of a bug."
    }

    $CopyRefreshTool_ScriptBlock = {
    #This script block uses SMB as the first try and PowerShell remoting (WinRM) as the second try
    #Note: PowerShell remoting will fail if a non-audit WDAC policy is on the remote machine (due to Constrained Language Mode)
        Param(
            $PSComputerName,
            $RemoteStagingDirectory,
            $RefreshToolPath
        )

        function Convert-ToSMBPath {
            Param (
                $Path,
                $ComputerName
            )

            $Root = Split-Path -Qualifier $Path
            if (($Root.Length -eq 2) -and ($Root[1] -eq ":")) {
                $Letter = $Root.Substring(0,1).ToLower()
                return (Join-Path "\\$ComputerName\$Letter`$\" -ChildPath (Split-Path -NoQualifier $Path))
            } else {
                return (Join-Path "\\$ComputerName" -ChildPath $Path)
            }
        }

        try {
            Copy-Item -Path $RefreshToolPath -Destination (Convert-ToSMBPath -Path $RemoteStagingDirectory -ComputerName $PSComputerName) -ErrorAction Stop
        } catch {
            try {
                $sess = New-PSSession -ComputerName $PSComputerName -ErrorAction Stop; 
                Copy-Item -ToSession $sess -Path (Join-Path $PSModuleRoot -ChildPath $ModulePath) -Destination "$TempDrive`:\Program Files\WindowsPowerShell\Modules\WDACAuditing\" -ErrorAction Stop
                $sess | Remove-PSSession
            } catch {
                #FIXME / TODO
                ##TODO: UseConstrainedLanguageMode workaround 
                #In other words: Provide an alternate method to copy files to remote when SMB isn't available and Constrained Language is enabled on remote.
            }
        }
    }

    $CopyCIPolicy_ScriptBlock = {
    #This script block uses SMB as the first try and PowerShell remoting (WinRM) as the second try
    #Note: PowerShell remoting will fail if a non-audit WDAC policy is on the remote machine (due to Constrained Language Mode)
        Param(
            $PSComputerName,
            $RemoteStagingDirectory,
            $CIPolicyPath
        )

        function Convert-ToSMBPath {
            Param (
                $Path,
                $ComputerName
            )

            $Root = (Split-Path -Qualifier $Path)
            if (($Root.Length -eq 2) -and ($Root[1] -eq ":")) {
                $Letter = $Root.Substring(0,1).ToLower()
                return (Join-Path "\\$ComputerName\$Letter`$\" -ChildPath (Split-Path -NoQualifier $Path))
            } else {
                return (Join-Path "\\$ComputerName\" -ChildPath $Path)
            }
        }

        try {
            Copy-Item -Path $CIPolicyPath -Destination (Convert-ToSMBPath -Path $RemoteStagingDirectory -ComputerName $PSComputerName) -Force -ErrorAction Stop
        } catch {
            try {
                $sess = New-PSSession -ComputerName $PSComputerName -ErrorAction Stop; 
                Copy-Item -ToSession $sess -Path $CIPolicyPath -Destination $RemoteStagingDirectory -Force -ErrorAction Stop
                $sess | Remove-PSSession
            } catch {
                #FIXME / TODO
                ##TODO: UseConstrainedLanguageMode workaround 
                #In other words: Provide an alternate method to copy files to remote when SMB isn't available and Constrained Language is enabled on remote.
            }
        }
    }

    $CopySignatureChecker_ScriptBlock = {
        Param(
            $PSComputerName,
            $TestValidWDACSignedPolicySignature_FilePath,
            $RemoteModulePath
        )

        function Convert-ToSMBPath {
            Param (
                $Path,
                $ComputerName
            )

            $Root = (Split-Path -Qualifier $Path)
            if (($Root.Length -eq 2) -and ($Root[1] -eq ":")) {
                $Letter = $Root.Substring(0,1).ToLower()
                return (Join-Path "\\$ComputerName\$Letter`$\" -ChildPath (Split-Path -NoQualifier $Path))
            } else {
                return (Join-Path "\\$ComputerName\" -ChildPath $Path)
            }
        }

        try {
            Copy-Item -Path $TestValidWDACSignedPolicySignature_FilePath -Destination (Convert-ToSMBPath -Path $RemoteModulePath -ComputerName $PSComputerName) -Force -ErrorAction Stop
        } catch {
            try {
                $sess = New-PSSession -ComputerName $PSComputerName -ErrorAction Stop; 
                Copy-Item -ToSession $sess -Path $CIPolicyPath -Destination $RemoteModulePath -Force -ErrorAction Stop
                $sess | Remove-PSSession
            } catch {
                #FIXME / TODO
                ##TODO: UseConstrainedLanguageMode workaround 
                #In other words: Provide an alternate method to copy files to remote when SMB isn't available and Constrained Language is enabled on remote.
            }
        }
    }

    $copyRefresh = $false; #Used to denote when a notice of refresh tool file copying should be written. (Verbose only.)
    $jobs = @()
    $sigVerificationToolCopyJobs = @()

    if (-not $SkipSetup) {
        #################################
        #Initial Remote in first!

        $sess = New-PSSession $Machines -ErrorAction SilentlyContinue

        if (-not $sess) {
            throw "Unable to establish remote powershell sessions with any designated device."
        }

        $Result = Invoke-Command -Session $sess -ArgumentList $RemoteStagingDirectory,$X86_Path,$AMD64_Path,$ARM64_Path,$Signed.ToBool() -ScriptBlock {
            Param (
                $RemoteStagingDirectory,
                $X86_Path,
                $AMD64_Path,
                $ARM64_Path,
                $Signed
            )

            $IsDirectoryPresent = $null
            $DirectoryPlacingError = $null
            $RefreshToolPresent = $null
            $TestValidWDACSignedPolicySignaturePresent = $null
            if (-not (Test-Path $RemoteStagingDirectory)) {
                try {
                    #Slash needs to be added to end of the qualifier \ drive name or else it gets put in the Documents folder
                    New-Item -Name (Split-Path -NoQualifier $RemoteStagingDirectory) -Path ((Split-Path -Qualifier $RemoteStagingDirectory) + "\") -ItemType "Directory" -ErrorAction Stop | Out-Null
                    $IsDirectoryPresent = $true
                    $RefreshToolPresent = $false
                } catch {
                    $IsDirectoryPresent = $false
                    $RefreshToolPresent = $false
                    $DirectoryPlacingError = $_
                }
            } else {
                $IsDirectoryPresent = $true
                if ((Test-Path (Join-Path $RemoteStagingDirectory -ChildPath (Split-Path -Leaf $X86_Path))) -or (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath (Split-Path -Leaf $ARM64_Path))) -or (Test-Path (Join-Path $RemoteStagingDirectory -ChildPath (Split-Path -Leaf $AMD64_Path)))) {
                #Note here that the names of the refresh tools are the names provided by initially in the LocalStorage.json file
                    $RefreshToolPresent = $true
                } else {
                    $RefreshToolPresent = $false
                }
                
                try {
                    Set-Location $RemoteStagingDirectory
                    Get-ChildItem * -Include *.cip | Remove-Item -ErrorAction Stop
                } catch {
                    Write-Verbose "Trouble with deleting previous .CIP files in WDAC staging directory."
                }
            }

            if ($Signed) {
                if (-not (Test-Path "$env:ProgramFiles\WindowsPowerShell\Modules\Test-ValidWDACSignedPolicySignature\")) {
                    New-Item -ItemType Directory -Path "$env:ProgramFiles\WindowsPowerShell\Modules" -Name "Test-ValidWDACSignedPolicySignature" -Force -ErrorAction SilentlyContinue
                    $TestValidWDACSignedPolicySignaturePresent = $false
                } else {
                    if (-not (Test-Path "$env:ProgramFiles\WindowsPowerShell\Modules\Test-ValidWDACSignedPolicySignature\Test-ValidWDACSignedPolicySignature.psm1")) {
                        $TestValidWDACSignedPolicySignaturePresent = $false
                    } else {
                        $TestValidWDACSignedPolicySignaturePresent = $true
                    }
                }
            }

            $Result = @()
            $Result += @{IsDirectoryPresent = $IsDirectoryPresent; DirectoryPlacingError = $DirectoryPlacingError; RefreshToolPresent = $RefreshToolPresent; TestValidWDACSignedPolicySignaturePresent = $TestValidWDACSignedPolicySignaturePresent; RemoteModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\Test-ValidWDACSignedPolicySignature\"}
            return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
        } -ErrorAction SilentlyContinue

        #I believe you have to remove the session here otherwise you can't make individual connections to the machines that you need to copy files to (if you aren't using SMB)
        $sess | Remove-PSSession
        #################################
       
        #Copy Refresh Tools
        $Result | ForEach-Object {

            $thisComputer = $_.PSComputerName
            if ($_.DirectoryPlacingError) {
                Write-Verbose "Error creating remote staging directory on $($_.PSComputerName) with error: $($_.DirectoryPlacingError)"
            }

            if ($_.IsDirectoryPresent -and ($_.RefreshToolPresent -eq $false)) {

                $CPUArchitecture = ($ComputerMap | Where-Object {$_.DeviceName -eq $thisComputer} | Select-Object CPU).CPU
                $resultRefreshToolPath = $null

                if ($CPUArchitecture -eq "AMD64") {
                    $resultRefreshToolPath = $AMD64_Path
                } elseif ($CPUArchitecture -eq "ARM64") {
                    $resultRefreshToolPath = $ARM64_Path
                } elseif ($CPUArchitecture -eq "X86") {
                    $resultRefreshToolPath = $X86_Path
                } else {
                    #Other CPU Architectures not supported
                    continue
                }

                $jobs += (Start-Job -Name ("CopyRefreshTool_" + $_.PSComputerName) -ScriptBlock $CopyRefreshTool_ScriptBlock -ArgumentList $_.PSComputerName,$RemoteStagingDirectory,$resultRefreshToolPath)
                if (-not $copyRefresh) {
                    Write-Verbose "Copying refresh tool to machines which don't have it."
                }
                $copyRefresh = $true
            }

            if ($Signed) {
                if ($_.TestValidWDACSignedPolicySignaturePresent -eq $false) {
                    $RemoteModulePath = $_.RemoteModulePath
                    $sigVerificationToolCopyJobs += (Start-Job -Name ("CopySignatureVerificationTool_" + $_.PSComputerName) -ScriptBlock $CopySignatureChecker_ScriptBlock -ArgumentList $_.PSComputerName,$TestValidWDACSignedPolicySignature_FilePath,$RemoteModulePath)
                }
            }
        }

        Write-Verbose ("Refresh tool copy job count: " + $jobs.Count)

        foreach ($job in $jobs) { 
            $job | Wait-Job | Out-Null
        }

        if ($sigVerificationToolCopyJobs.Count -ge 1) {
            Write-Verbose "Copying signature verify tool to machines which don't have it"
        }

        Write-Verbose ("Signature verify tool copy job count: " + $sigVerificationToolCopyJobs.Count)

        foreach ($job in $sigVerificationToolCopyJobs) {
            $job | Wait-Job | Out-Null
        }
    }

    #Copy CI Policy
    $jobs = @()
    foreach ($RemoteMachine in $Machines) {
        $jobs += (Start-Job -Name ("CopyCIPolicy_" + $RemoteMachine) -ScriptBlock $CopyCIPolicy_ScriptBlock -ArgumentList $RemoteMachine,$RemoteStagingDirectory,$CIPolicyPath)
    }
    
    Write-Verbose ("CI policy copy job count: " + $jobs.Count)

    $iterator = 0
    foreach ($job in $jobs) {
        if ($iterator = 0) {
            Write-Host "Copying WDAC / Code Integrity policies to remote machines..."
        }
        $job | Wait-Job | Out-Null
        $iterator += 1
    }
}

Export-ModuleMember -Function Copy-StagedWDACPolicies

