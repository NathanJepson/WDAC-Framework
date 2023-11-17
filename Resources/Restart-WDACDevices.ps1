function Restart-WDACDevices {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("PC","Computer","Computers","Device","PCs","Workstation","Workstations")]
        [string[]]$Devices
    )

    $scriptLogOutUsers = {
        
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
        
        Start-Sleep -Seconds 14
    }

    Invoke-Command -ComputerName $Devices -ScriptBlock $scriptLogOutUsers -ErrorAction SilentlyContinue
    Restart-Computer -ComputerName $Devices -Force -ErrorAction SilentlyContinue
}