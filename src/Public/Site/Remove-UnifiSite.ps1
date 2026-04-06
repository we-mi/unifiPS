function Remove-UnifiSite {
    <#
    .SYNOPSIS
        Remove a unifi site
    .DESCRIPTION
        Remove a unifi site
    .EXAMPLE
        PS C:\> Get-UnifiSite "not_my_production_site" | Remove-UnifiSite
        Will try to get the Unifi.Site-Object for "not_my_production_site" and attempts to delete it
    .OUTPUTS
        Nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]

    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="String")]
        [String]$SiteName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="Object")]
        [Unifi.Site]$SiteObject
    )

    begin {
        # Get a list of all users or just us before we do anything
        $allSites = Get-UnifiSite
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq "String") {
            # we only got a username. Get the Unifi-Object of it
            $SiteObject = $allSites | Where-Object { $_.Name -eq $SiteName }
        }

        $Body = @{
            site = $SiteObject.ID
            cmd = "delete-site"
        }

        $Method = "POST"
        $Route = "s/{0}/cmd/sitemgr" -f $SiteObject.InternalName

        if ( $PSCmdlet.ShouldProcess($SiteObject.Name, "Remove unifi site") ) {
            $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
        }
    }
}
