function Get-UnifiSelf {
    <#
    .SYNOPSIS
        Shows information about the currently logged in user
    .DESCRIPTION
        Shows information about the currently logged in user
    .EXAMPLE
        PS C:\> Get-UnifiSelf
        Shows information about the currently logged in user
    .OUTPUTS
        Returns an object of type 'Unifi.User'
    #>
    [CmdletBinding()]
    [OutputType([Unifi.User])]

    param()

    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "self"

        [Unifi.User]::new($jsonResult)
    }
}
