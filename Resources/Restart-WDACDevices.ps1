function Restart-WDACDevices {
    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("PC","Computer","Computers","Device","PCs","Workstation","Workstations")]
        [string[]]$Devices
    )

    Restart-Computer -ComputerName $Devices -Force -ErrorAction SilentlyContinue
}