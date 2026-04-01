function Get-UnifiSite {
    <#
    .SYNOPSIS
        Gets one or more sites of the unifi controller
    .DESCRIPTION
        Gets one or more sites of the unifi controller
        You can filter by SiteName (internal site name) or SiteID or SiteDisplayName (name visible in the web interface, unifi's internal name for this field is 'desc')
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName *
        Lists all sites
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Default","*Test*"
        Lists all sites which contains the string "Test" and the site with the name "Default"
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteName "67itznop"
        Lists the site with the SiteName '67itznop'
    .EXAMPLE
        PS C:\> Get-UnifiSite SiteID "623e1bf66a5d4f1280160b7e"
        Lists the site with the ID '623e1bf66a5d4f1280160b7e'
    .OUTPUTS
        Returns JSON-Data
    #>
    [CmdletBinding(DefaultParameterSetName="SiteDisplayName")]
    [OutputType([Object])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter()]
        [String[]]
        $SiteName,

        # ID of the site
        [Parameter()]
        [String[]]
        $SiteID,

        # friendlyName of the site (Unifi's internal name for this field is 'desc'). This is the value visible in the web interface
        [Parameter()]
        [Alias("SiteDescription")]
        [Alias("Name")]
        [String[]]
        $SiteDisplayName
    )

    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "self/sites"

        if ( ![String]::IsNullOrWhiteSpace($Name) ) {
            $jsonResult = $jsonResult | Where-Object { $_.Name -like $Name }
        }

        if ( ![String]::IsNullOrWhiteSpace($Email) ) {
            $jsonResult = $jsonResult | Where-Object { $_.email -like $Email }
        }

        foreach ($site in $jsonResult) {
            [Unifi.Site]::new($site)
        }
    }
}
