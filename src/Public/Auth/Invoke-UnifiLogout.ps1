function Invoke-UnifiLogout {
    <#
    .SYNOPSIS
        Logs out of the unifi server and destroys the websession
    .DESCRIPTION
        Logs out of the unifi server and destroys the websession
    .EXAMPLE
        PS C:\> Invoke-UnifiLogout
        Logs out of the server
    .OUTPUTS
        Returns $True on Success
        Throws an exception on error
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param()

    process {
        $null = Invoke-UnifiRestCall -Method POST -Route "logout"

        Write-Verbose "Logout from Unifi-Controller successful"
        
        $True
    }
}
