function Convert-CIToolVersion {
    <#
    .SYNOPSIS
    Convert version numbers from CiTool to human-readable version numbers.

    .DESCRIPTION
    The CiTool will output large numbers for policy versions which have no resemblence to the "normal" version numbers with dots
    within a WDAC policy. Input that "large" number into this cmdlet to get the human-readable equivalent. 

    .PARAMETER VersionNumber
    The Version number of a policy when using "CiTool --list-policies"

    Author: Nathan Jepson
    License: MIT License
    #>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [Alias("Number","Version")]
        [string]$VersionNumber
    )

    $BinaryRepresentation = [convert]::ToString($VersionNumber,2)

    while ($BinaryRepresentation.Length -lt 64) {
        $BinaryRepresentation = "0" + $BinaryRepresentation
    }

    $str1 = $BinaryRepresentation.Substring(0,16)
    $str2 = $BinaryRepresentation.Substring(16,16)
    $str3 = $BinaryRepresentation.Substring(32,16)
    $str4 = $BinaryRepresentation.Substring(48,16)

    $result = [string]([convert]::ToInt32($str1,2)) + "." + [string]([convert]::ToInt32($str2,2)) + "." + [string]([convert]::ToInt32($str3,2)) + "." + [string]([convert]::ToInt32($str4,2))
    return $result
}

Export-ModuleMember -Function Convert-CIToolVersion