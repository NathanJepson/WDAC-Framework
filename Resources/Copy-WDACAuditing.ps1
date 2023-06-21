function Copy-WDACAuditing {

    param(
        [string[]]$RemoteMachine,
        [string]$PSModuleRoot,
        [string]$ModulePath
    )

    $sess = New-PSSession $RemoteMachine -ErrorAction SilentlyContinue

    if (-not $sess) {
        throw "PowerShell remoting not available to these devices.";
        return;
    }

    $Result = Invoke-Command -ErrorAction SilentlyContinue -Session $sess -ScriptBlock {
        $IsModulePresent = Test-Path "$($Env:Programfiles)\WindowsPowerShell\Modules\WDACAuditing\WDACAuditing.psm1"
        if (-not ($IsModulePresent)) {
            New-Item -ItemType Directory -Name "WDACAuditing" -Path "$($Env:Programfiles)\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue | Out-Null
        }
        $SysDrive = $null
        if ($PSVersionTable.PSEdition -eq "Core") {
            $SysDrive =  (Get-CimInstance -Class Win32_OperatingSystem -ComputerName localhost -Property SystemDrive | Select-Object -ExpandProperty SystemDrive)
        } elseif ($PSVersionTable.PSEdition -eq "Desktop") {
            $SysDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
        } else {
        #Otherwise, attempt to probe C:\ as the primary Windows drive in the rest of the script (failing if needed)
            $SysDrive = "C:"
        }

        $Result = @()
        $Result += @{IsModulePresent = $IsModulePresent; SysDrive = $SysDrive}
        return ($Result | ForEach-Object {New-Object -TypeName pscustomobject | Add-Member -NotePropertyMembers $_ -PassThru})
    }

    #I believe you have to remove the session here otherwise you can't make individual connections to the machines that you need to copy files to (if you aren't using SMB)
    $sess | Remove-PSSession

    $iterator = 0; #Used to denote when a notice of file copying should be written.
    $jobs = @()
    $Result | ForEach-Object {
        if (-not $_.IsModulePresent -and $_.SysDrive) {
        #Case: Module WDACAuditing.psm1 is not yet installed on the remote machine
            if ($iterator -eq 0) {
                Write-Host "Copying module WDACAuditing to machines which don't have it...."
            }

            $TempDrive = ( ($_.SysDrive -split '\:')[0])
            
            $ScriptBlock = {
            #This script block uses SMB as the first try and PowerShell remoting (WinRM) as the second try
            #Note: PowerShell remoting will fail if a non-audit WDAC policy is on the remote machine (due to Constrained Language Mode)
                Param(
                    $PSComputerName,
                    $TempDrive,
                    $PSModuleRoot,
                    $ModulePath
                )

                try {
                    Copy-Item -Path (Join-Path $PSModuleRoot -ChildPath $ModulePath) -Destination "\\$PSComputerName\$TempDrive`$\Program Files\WindowsPowerShell\Modules\WDACAuditing\" -ErrorAction Stop
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
            
            $jobs += (Start-Job -Name ("CopyWDACAuditing_" + $_.PSComputerName) -ScriptBlock $ScriptBlock -ArgumentList $_.PSComputerName,$TempDrive,$PSModuleRoot,$ModulePath)
            $iterator += 1;
        }
    }

    Write-Verbose ("Copy job count: " + $jobs.Count)

    foreach ($job in $jobs) {
        $job | Wait-Job | Out-Null
    }
}