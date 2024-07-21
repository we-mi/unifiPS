function New-UnifiSite {
    <#
    .SYNOPSIS
        Creates a new unifi site
    .DESCRIPTION
        Creates a new unifi site.
        It does check if a site with the same name is already present (You can have more than one site with the same DisplayName in the unifi controller (a bit stupid if you ask me...))
        If you want to disable this check, use the 'DisableNameCheck'-Switch
    .EXAMPLE
        PS C:\> New-UnifiSite -SiteDisplayName "My New Site"
        Creates the new unifi site 'My New Site'
    .EXAMPLE
        PS C:\> New-UnifiSite -SiteDisplayName "My New Site" DisableNameCheck
        Creates the new unifi site 'My New Site' even if a site with this DisplayName is already present
    .OUTPUTS
        Returns JSON-Data from the newly created site
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # (Display-)Name of the site under which it appears in the webui
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 0 )]
        [String]
        $SiteDisplayName,

        # Disable checking if a site name is already present
        [Parameter(Mandatory = $false)]
        [switch]
        $DisableNameCheck,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        try {

            if (!$DisableNameCheck) {
                $sites = Get-UnifiSite "*"

                if ($sites.SiteDisplayName -contains $SiteDisplayName) {
                    Write-Error "There's already a site with the DisplayName '$SiteDisplayName' present."
                    return ""
                }
            }

            $Body = @{
                cmd = "add-site"
                desc = $SiteDisplayName
            } | ConvertTo-Json

            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/default/cmd/sitemgr" -Body $Body

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Site '$SiteDisplayName' successfully created"

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$_.name}},
                                                        @{N="SiteID";E={$_._id}},
                                                        @{N="SiteDisplayName";E={$_.desc}}

                }
            } else {
               Write-Error "Site '$SiteDisplayName' was NOT created ($jsonResult.meta.msg)"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new site $($SiteDisplayName) ($_)"
        }
    }
}
