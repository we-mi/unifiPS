function Get-UnifiTag {
    <#
    .SYNOPSIS
        Gets all tags from a unifi site
    .DESCRIPTION
        Gets all tags from a unifi site
    .EXAMPLE
        PS C:\> Get-UnifiTag -SiteName "default"
        Get all tags from the "default" site
    .OUTPUTS
        Returns JSON-Data
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        try {

            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/tag"

            if ($jsonResult.meta.rc -eq "ok") {
                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="TagID";E={$_._id}},
                                                        @{N="TagName";E={$_.name}},
                                                        @{N="TagMembers";E={$_.member_table}}
                }
            }

        } catch {
            Write-Warning "Something went wrong while fetching tags for site '$($SiteName)' ($_)"
        }
    }
}
