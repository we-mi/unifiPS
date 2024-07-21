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
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param()

    process {
        $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/logout"

        if ($jsonResult.meta.rc -eq "ok") {
            Write-Verbose "Logout from Unifi-Controller successful"
            return $True
        } else {
            Write-Error "Logout from Unifi-Controller failed"
            return $False
        }

    }
}
