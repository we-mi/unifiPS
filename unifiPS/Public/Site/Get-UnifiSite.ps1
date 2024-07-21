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
        [Parameter( ParameterSetName = "SiteName", Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String[]]
        $SiteName,

        # ID of the site
        [Parameter( ParameterSetName = "SiteID", Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String[]]
        $SiteID,

        # friendlyName of the site (Unifi's internal name for this field is 'desc'). This is the value visible in the web interface
        [Parameter( ParameterSetName = "SiteDisplayName", Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0 )]
        [Alias("SiteDescription")]
        [String[]]
        $SiteDisplayName,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/self/sites"

            if ($jsonResult.meta.rc -eq "ok") {

                switch ($PSCmdlet.ParameterSetName) {
                    "SiteName" {
                        $tmpList = @()
                        foreach($singleSiteName in $SiteName) {
                            $tmpList += $jsonResult.data | Where-Object { $_.Name -like $singleSiteName }
                        }
                        $jsonResult.data = $tmpList
                    }
                    "SiteID" {
                        $tmpList = @()
                        foreach($singleSiteID in $SiteID) {
                            $tmpList += $jsonResult.data | Where-Object { $_._id -like $singleSiteID }
                        }
                        $jsonResult.data = $tmpList
                    }
                    "SiteDisplayName" {
                        $tmpList = @()
                        foreach($singleSiteDisplayName in $SiteDisplayName) {
                            $tmpList += $jsonResult.data | Where-Object { $_.desc -like $singleSiteDisplayName }
                        }
                        $jsonResult.data = $tmpList
                    }
                }

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteID";E={$_._id}},
                                                        @{N="SiteDisplayName";E={$_.desc}},
                                                        @{N="SiteName";E={$_.name}},
                                                        @{N="NoDelete";E={ if ($_.attr_no_delete) {$_.attr_no_delete} else { $False }}}
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
    }
}
