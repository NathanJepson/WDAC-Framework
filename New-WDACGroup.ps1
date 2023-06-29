function New-WDACGroup {
    <#
    .SYNOPSIS
    Create a new group which devices can be assigned to (WDAC policies are assigned to groups.)

    .DESCRIPTION
    Utilizes SQLite to be able to create another entry in the "Groups" table within the trust database.

    .PARAMETER GroupName
    The name of this new group.

    .EXAMPLE
    New-WDACGroup Cashiers

    .EXAMPLE
    New-WDACGroup -GroupName "Top Floor"
    #>

    [cmdletbinding()]
    Param ( 
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )

    try {
        if (New-WDACGroup_SQL -GroupName $GroupName -ErrorAction Stop) {
            Write-Host "Group created successfully."
        } else {
            throw "Unsuccessful attempt to create new group."
        }
    } catch {
        Write-Error $_
    }
}