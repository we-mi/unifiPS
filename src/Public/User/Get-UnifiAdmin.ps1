function Get-UnifiAdmin {
    <#
    .SYNOPSIS
        List unifi admins
    .DESCRIPTION
        List unifi admins
    .EXAMPLE
        PS C:\> Get-UnifiAdmin
        List unifi admins
    .EXAMPLE
        PS C:\> Get-UnifiAdmin -Name *admin*
        List all unifiadmins which have "admin" in their names
    .OUTPUTS
        Returns an array of 'Unifi.User'
    #>
    [CmdletBinding()]
    [OutputType([Unifi.User[]])]

    param(
        [Parameter()]
        [String]$Name,

        [Parameter()]
        [String]$Email
    )

    process {

        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "stat/admin"

        if ( ![String]::IsNullOrWhiteSpace($Name) ) {
            $jsonResult = $jsonResult | Where-Object { $_.Name -like $Name }
        }

        if ( ![String]::IsNullOrWhiteSpace($Email) ) {
            $jsonResult = $jsonResult | Where-Object { $_.email -like $Email }
        }

        foreach ($user in $jsonResult) {
            [Unifi.User]::new($user)
        }

    }
}
