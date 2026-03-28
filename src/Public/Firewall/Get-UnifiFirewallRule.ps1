function Get-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Lists firewall rules in a site
    .DESCRIPTION
        Lists firewall rules in a site
    .EXAMPLE
        PS C:\> Get-UnifiSite "default" | Get-UnifiFirewallRule
        Lists all rules in the default site
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
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/firewallrule"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="RuleName";E={$_.Name}},
                                                        @{N="RuleID";E={$_._id}},
                                                        @{N="RuleSet";E={$_.ruleset}},
                                                        @{N="Enabled";E={$_.enabled}},
                                                        @{N="Action";E={$_.action}},
                                                        @{N="DstAddress";E={$_.dst_address}},
                                                        @{N="DstFirewallGroupIDs";E={$_.dst_firewallgroup_ids}},
                                                        @{N="DstNetworkConfID";E={$_.dst_networkconf_id}},
                                                        @{N="DstNetworkConfType";E={$_.dst_networkconf_type}},
                                                        @{N="IcmpTypename";E={$_.icmp_typename}},
                                                        @{N="IPSEC";E={$_.ipsec}},
                                                        @{N="Logging";E={$_.logging}},
                                                        @{N="Protocol";E={$_.protocol}},
                                                        @{N="ProtocolMatchExcepted";E={$_.protocol_match_excepted}},
                                                        @{N="RuleIndex";E={$_.rule_index}},
                                                        @{N="SrcAddress";E={$_.src_address}},
                                                        @{N="SrcFirewallGroupIDs";E={$_.src_firewallgroup_ids}},
                                                        @{N="SrcMACAddress";E={$_.src_mac_address}},
                                                        @{N="SrcNetworkConfID";E={$_.src_networkconf_id}},
                                                        @{N="SrcNetworkConfType";E={$_.src_networkconf_type}},
                                                        @{N="StateEstablished";E={$_.state_established}},
                                                        @{N="StateInvalid";E={$_.state_invalid}},
                                                        @{N="StateNew";E={$_.state_new}},
                                                        @{N="StateRelated";E={$_.state_related}},
                                                        @{N="SettingPreference";E={$_.setting_preference}}
                }
            }

        } catch {
            Write-Warning "Something went wrong while fetching firewall rules for site $($SiteName) ($_)"
        }
    }
}
