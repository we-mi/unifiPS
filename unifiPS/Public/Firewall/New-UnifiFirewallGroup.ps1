function New-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Creates a new firewall group in a site
    .DESCRIPTION
        Creates a new firewall group in a site

        Ports can be separated by a comma (20,21,22) and/or specified as a range (5900-5910)
        IP-Address can also be separated by a comma and/or specified as a network address (10.0.0.0/8)
    .EXAMPLE
        PS C:\> New-UnifiFirewallGroup -SiteName "default" -GroupName "FTP-Ports" -GroupMembers 20,21 -GroupType port-group
        Creates the firewall group "FTP-Ports" in the default site as a "port-group" and assigns the ports 20&21 to it
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteName "Production" | New-UnifiFirewallGroup -GroupName "Internal Networks" -GroupType "address-group" -GroupMembers "192.168.0.0/24","192.168.100.0/24"
        Creates the firewall group "Internal Networks" in the "Production" site as an "address-group" and assigns the networks 192.168.0.0/24 and 192.168.100.0/24 to it
    .OUTPUTS
        Returns JSON-Data for the newly created object
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
        $Raw,

        # Name of the Firewall group to be created
        [Parameter(
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupName,

        # Type of the Firewall group to be created (one of "address-group","ipv6-address-group","port-group")
        [Parameter(
            Mandatory = $true
        )]
        [ValidateSet("address-group","ipv6-address-group","port-group")]
        [string]
        $GroupType,

        # Group members (can be ipv4/ipv6 addresses or port numbers/ranges). Can also be empty
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $GroupMembers = @()
    )

    process {
        try {

            $Body = @{
                name = $GroupName
                group_type = $GroupType
                group_members = $GroupMembers
            } | ConvertTo-Json

            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/rest/firewallgroup" -Body $Body

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Firewall group '$GroupName' successfully created for site '$SiteName'"

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="FirewallGroupID";E={$_._id}},
                                                        @{N="FirewallGroupName";E={$_.name}},
                                                        @{N="FirewallGroupMembers";E={$_.group_members}},
                                                        @{N="FirewallGroupType";E={$_.group_type}}

                }
            } else {
                if ($jsonResult.meta.msg -eq "api.err.FirewallGroupExisted") {
                    Write-Warning "Firewall group '$GroupName' already exists in site '$SiteName'"
                } else {
                    Write-Error "Firewall group '$GroupName' was NOT created for site '$SiteName'"
                }
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $($SiteName) ($_)"
        }
    }
}
