function Get-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Lists firewall groups in a site
    .DESCRIPTION
        Lists firewall groups in a site.
        A firewall group can be a group of ports, ipv4-addresses or ipv6-addresses. This group is then used in a firewall rule
    .EXAMPLE
        PS C:\> Get-UnifiFirewallGroup -SiteName "default"
        Lists the firewall groups for the default site
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
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/firewallgroup"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="GroupID";E={$_._id}},
                                                        @{N="GroupName";E={$_.name}},
                                                        @{N="GroupMembers";E={$_.group_members}},
                                                        @{N="GroupType";E={$_.group_type}}
                }
            }
        } catch {
            Write-Warning "Something went wrong while fetching firewall groups for site $($SiteName) ($_)"
        }
    }
}
