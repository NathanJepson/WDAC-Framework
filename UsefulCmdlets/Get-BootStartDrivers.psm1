$ThisIsASignedModule = $false
if ((Split-Path ((Get-Item $PSScriptRoot).Parent) -Leaf) -eq "SignedModules") {   
    $ThisIsASignedModule = $true
}

function Format-BootLogFileLine {
    [CmdletBinding()]
    Param (
        $line,
        $remoteSysRoot
    )

    if ( ($null -eq $line) -or (" " -eq $line) -or ("" -eq $line)) {
        Write-Warning "Boot log file shows one driver as an empty file path."
        return
    }

    try {
        if ($line.Substring(0,12) -eq "\SystemRoot\") {
            if ($remoteSysRoot) {
                return ($line -replace '\\SystemRoot\\',"$remoteSysRoot\")
            } else {
                #return ($line -replace '\\SystemRoot\\','$env:SystemRoot\')
                throw "Remote system root not resolved."
            }
        } elseif ($line.Substring(0,7) -match "\\\?\?\\[a-zA-Z]\:\\") {
            $DriveChar = "$($line[4])".ToUpper()
            return ($line -replace "\\\?\?\\[a-zA-Z]\:\\","$($DriveChar):\")
        } else {
            throw "Unhandled file-path type in line parser in the Format-BootLogFileLine function."
        }
    } catch {
        throw ($_ | Format-List -Property * | Out-String)
    }
}

function Get-BootStartDrivers {
    <#
    .SYNOPSIS
    This cmdlet allows you to get file information on boot-start drivers so you can begin the process of trusting them.
    Utilizes Get-WDACFiles cmdlet.
    Based on the filepath of the boot-log file you specify (usually "C:\Windows\ntbtlog.txt", but make sure to enable "Boot log" in the System Configuration
    menu in Windows so that it's actually there), scan the specified file-paths of the boot-start files listed there.

    .DESCRIPTION
    The ntbtlog.txt file (or whatever boot-log file you specify) will be parsed to extract every directory used in the bootstart process. 
    Then, a scan will parse every one of those file directories (this takes a while unfortunately.).
    The cmdlet will attempt to deduce which subdirectories will not be needed and provide them to the "OmitFilePaths" parameter when scanning
    for drivers. For some reason, OmitFilePaths never excludes " C:\WINDOWS\Installer" and "C:\WINDOWS\BitLockerDiscoveryVolumeContents" 
    and "C:\WINDOWS\ELAMBKUP" despite trying.

    Author: Nathan Jepson
    License: MIT License
   
    .PARAMETER RemoteMachine
    The remote machine that you would like to grab boot start file information from (omit this parameter to scan locally)

    .PARAMETER AllTime
    When this parameter is specified, the whole log file is parsed, not just the most recent boot time.
    
    .PARAMETER BootLogFile
    The file-path of the boot log text file to grab file information from (usually this is "C:\Windows\ntbtlog.txt", but you need to enable "Boot log" in system configuration)
    
    .PARAMETER LoadedDriversOnly
    Specify this switch when you only want to consider drivers that were loaded as indicated by BOOTLOG_LOADED

    .PARAMETER NoScript
    Specify that you don't want to include scripts in the scan (recommended)
    #>

    [CmdletBinding()]
    Param (
        [Alias("Computer","PC","Machine")]
        [string]$RemoteMachine,
        [switch]$AllTime,
        [Alias("Log","LogFile")]
        [string]$BootLogFile,
        [Alias("BootLogLoaded","Bootlog_loaded")]
        [switch]$LoadedDriversOnly,
        [switch]$NoScript
    )

    if ($ThisIsASignedModule) {
        Write-Verbose "The current file is in the SignedModules folder."
    }

    $BootStartDrivers = @()

    $LogFileParseScriptBlock = {
        $InputArray = @($input)
        $AllTime = $InputArray[0]
        $LoadedDriversOnly = $InputArray[1]
        $BootLogFile = $InputArray[2]
        $result = @()

        if (-not (Test-Path $BootLogFile)) {
            throw "The path $BootLogFile does not exist on remote machine."
        }

        $LineStart = 0
        if (-not $AllTime) {
            #This gets the last boot start date-time line
            $LineStart = ((Select-String -Pattern '(\d| )\d\d?  ?\d\d? \d{4} \d\d?\:\d\d\:\d\d' -Path $BootLogFile | Sort-Object LineNumber -Descending)[0]).LineNumber
            if ($null -eq $LineStart) {
                throw "BUG: Unable to retrieve DateTime line for the logfile parse starting point."
            }
        }
        
        $FileContent = Get-Content -Path $BootLogFile -ErrorAction Stop
        for ($i=$LineStart; $i -lt $FileContent.Count; $i++) {
            $MatchExpression = "BOOTLOG_(NOT_)?LOADED"
            if ($LoadedDriversOnly) {
                $MatchExpression = "BOOTLOG_LOADED"
            }
            if ($FileContent[$i] -match $MatchExpression) {
                #You can't use the regex from the if-statement or you get multiple matches -- and therefore can't use it when splitting
                $theFilePath = ($FileContent[$i] -split "BOOTLOG_\w*LOADED ")[1]
                $result += $theFilePath
            }
        }

        return $result,"$($env:SystemRoot)"
    }

    $GetOmittedPaths = {
        $InputArray = @($input)
        $result = @{}
        $DirectoryMap = $InputArray[0]
        foreach ($Dir in $DirectoryMap.Keys) {
            $result[$Dir] = ((Get-ChildItem -Path $Dir -Directory) | Select-Object FullName).FullName
        }
        return $result
    }

    if ($RemoteMachine) {
        $sess = New-PSSession -ComputerName $RemoteMachine -ErrorAction Stop
        if ($sess) {
            Write-Verbose "Parsing log file..."
            $result,$remoteSysRoot = $AllTime,$LoadedDriversOnly,$BootLogFile | Invoke-Command -Session $sess -ScriptBlock $LogFileParseScriptBlock -ErrorAction Stop
            if ($result.Count -le 0) {
                throw "No valid results from log file."
            }
            if (($null -eq $remoteSysRoot) -or ("" -eq $remoteSysRoot)) {
                throw "Remote SystemRoot not resolved."
            }

            $DirectoryMap = @{}
            $FilePathsMap = @{}
            foreach ($line in $result) {
                $FormattedLine = Format-BootLogFileLine -line $line -remoteSysRoot $remoteSysRoot -ErrorAction Stop
                if ($null -eq $FormattedLine) {
                    continue;
                }
                if (-not ($FilePathsMap[$FormattedLine])) {
                    $FilePathsMap += @{$FormattedLine = $true}
                }
            }

            foreach ($Path in $FilePathsMap.Keys) {
                $Dir = Split-Path $Path
                if (-not ($DirectoryMap[$Dir])) {
                    $DirectoryMap += @{$Dir = $true}
                }
            }

            #For each scan, we are basically getting going to exclude every subdirectory contained in every directory, 
            #...since we'll do a scan for every directory manually
            #...e.g., C:\Windows THEN C:\Windows\System32
            #...i.e., the Only thing the matters is a file's immediate parent directory.
            Write-Verbose "Obtaining directories to exclude..."
            $DirectoryMap = $DirectoryMap | Invoke-Command -Session $sess -ScriptBlock $GetOmittedPaths -ErrorAction Stop
            
            foreach ($Directory in $DirectoryMap.Keys) {
                Write-Verbose "Scanning directory $Directory ..."

                $ScannedFilesBundle = Get-WDACFiles -NoShadowCopy -ScanPath $Directory -OmitPaths ([string[]]($DirectoryMap[$Directory])) -UserPEs -NoScript:$NoScript -RemoteMachine $RemoteMachine
                foreach ($ScannedFile in $ScannedFilesBundle) {
                    if ($FilePathsMap[$ScannedFile.FilePath]) {
                        $BootStartDrivers += $ScannedFile
                    } else {
                        Write-verbose "Skpping file $($ScannedFile.FilePath) because it's not a boot start driver."
                    }
                }
            }
        }
    } else {
        if (-not (Test-Path $BootLogFile)) {
            throw "The path $BootLogFile does not exist on local machine."
        }
    }

    return $BootStartDrivers
}


Export-ModuleMember -Function Get-BootStartDrivers