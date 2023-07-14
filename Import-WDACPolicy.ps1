function Import-WDACPolicy {
    [CmdletBinding()]
    Param (
        [ValidatePattern('\.xml$')]
        [ValidateScript({Test-Path $_}, ErrorMessage = "Cannot find the file that you provided.")]
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    return $null
}