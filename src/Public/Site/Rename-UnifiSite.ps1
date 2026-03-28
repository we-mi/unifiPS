function Rename-UnifiSite {
    <#
    .SYNOPSIS
        Renames a unifi site
    .DESCRIPTION
        Renames a unifi site
    .EXAMPLE
        PS C:\> Rename-UnifiSite -SiteName '67itznop' -NewSiteDisplayName "my wonderful site"
        Renames the unifi site with the SiteName '67itznop' to 'my wonderful site'. Note that the SiteName keeps the same. Only the SiteDisplayName in the webui changes
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteDisplayName 'Development' | Rename-UnifiSite
        Renames the unifi site with the SiteName '67itznop' to 'my wonderful site'. Note that the SiteName keeps the same. Only the SiteDisplayName in the webui changes
    .OUTPUTS
        Returns JSON-Data
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Name of the site which will be renamed (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # New DisplayName of the site
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [Alias("SiteDisplayName")]
        [String]
        $NewSiteDisplayName,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        try {
            $site = Get-UnifiSite -SiteName $SiteName

            if ($site) {

                if ($site.SiteDisplayName -eq $NewSiteDisplayName) {
                    Write-Warning "Nothing to do. Old and new display names match"
                } else {

                    $Body = @{
                        desc = $NewSiteDisplayName
                        cmd = "update-site"
                    } | ConvertTo-Json

                    $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body $Body

                    if ($jsonResult.meta.rc -eq "ok") {
                        Write-Verbose "Site '$($SiteName)' was renamed from '$($site.NewSiteDisplayName)' to '$NewSiteDisplayName'"
                        if ($Raw) {
                            $jsonResult.data
                        } else {
                            $jsonResult.data | Select-Object    @{N="SiteID";E={$_._id}},
                                                                @{N="NewSiteDisplayName";E={$_.desc}},
                                                                @{N="SiteName";E={$_.name}},
                                                                @{N="NoDelete";E={ if ($_.attr_no_delete) {$_.attr_no_delete} else { $False }}}
                        }

                    } else {
                        Write-Error "Site '$($SiteName)' (DisplayName: $($site.NewSiteDisplayName)) was NOT renamed"
                    }
                }
            } else {
                Write-Error "No site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while renaming site $($SiteName) ($_)"
        }
    }
}
