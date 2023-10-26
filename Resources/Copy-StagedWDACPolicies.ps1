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
        [switch]$SkipSetup
    )

    if (($null -eq $X86_Path) -and ($null -eq $AMD64_Path) -and ($null -eq $ARM64_Path)) {
        throw "No paths for refresh policy .exe tools provided to function."
    }
   
    if (-not $FixDeferred) {
        if ($Test) {
            $Machines = ($ComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($_.TestMachine -eq $true) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
        } else {
            $Machines = ($ComputerMap | Where-Object {($_.NewlyDeferred -eq $false) -and ($null -ne $_.CPU)} | Select-Object DeviceName).DeviceName
        }
    } else {
        #TODO
        throw "Operation not currently supported for fixing deferred" #FIXME
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
                $Letter = $Root.Substring(0,1)
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
                $Letter = $Root.Substring(0,1)
                return (Join-Path "\\$ComputerName\$Letter`$\" -ChildPath (Split-Path -NoQualifier $Path))
            } else {
                return (Join-Path "\\$ComputerName\" -ChildPath $Path)
            }
        }

        try {
            Copy-Item -Path $CIPolicyPath -Destination (Convert-ToSMBPath -Path $RemoteStagingDirectory -ComputerName $PSComputerName) -ErrorAction Stop
        } catch {
            try {
                $sess = New-PSSession -ComputerName $PSComputerName -ErrorAction Stop; 
                Copy-Item -ToSession $sess -Path $CIPolicyPath -Destination $RemoteStagingDirectory -ErrorAction Stop
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

    if (-not $SkipSetup) {
        #################################
        #Initial Remote in first!

        $sess = New-PSSession $Machines -ErrorAction SilentlyContinue

        if (-not $sess) {
            throw New-Object System.Management.Automation.Remoting.PSRemotingTransportException
        }

        $Result = Invoke-Command -ErrorAction SilentlyContinue -Session $sess -ArgumentList $RemoteStagingDirectory,$X86_Path,$AMD64_Path,$ARM64_Path -ScriptBlock {
            Param (
                $RemoteStagingDirectory,
                $X86_Path,
                $AMD64_Path,
                $ARM64_Path
            )

            $IsDirectoryPresent = $null
            $DirectoryPlacingError = $null
            $RefreshToolPresent = $null

            if (-not (Test-Path $RemoteStagingDirectory)) {
                try {
                    New-Item -ItemType Directory -Name (Split-Path -NoQualifier $RemoteStagingDirectory) -Path (Split-Path -Qualifier $RemoteStagingDirectory) -ErrorAction Stop | Out-Null
                    $IsDirectoryPresent = $true
                } catch {
                    $IsDirectoryPresent = $false
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
            }

            $Result = @()
            $Result += @{IsDirectoryPresent = $IsDirectoryPresent; DirectoryPlacingError = $DirectoryPlacingError; RefreshToolPresent = $RefreshToolPresent}
            return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
        }

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
        }

        Write-Verbose ("Refresh tool copy job count: " + $jobs.Count)

        foreach ($job in $jobs) { 
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

