function Get-UnifiAdmin {
    <#
    .SYNOPSIS
        List unifi admins
    .DESCRIPTION
        List unifi admins
    .EXAMPLE
        PS C:\> Get-UnifiAdmin
        List unifi admins
    .OUTPUTS
        Returns an array of 'Unifi.User'
    #>
    [CmdletBinding()]
    [OutputType([Unifi.User[]])]

    param()

    process {

        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "stat/admin"

        foreach ($user in $jsonResult) {
            [Unifi.User]::new($user)
        }
        
    }
}
