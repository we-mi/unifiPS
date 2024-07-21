function Edit-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Edits a firewall rule in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Edit-UnifiFirewallRule TODO
    .EXAMPLE
        PS C:\> TODO
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

        # ID of the Firewall group to be edited
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $RuleID,

        # Name of the Firewall rule to be edited
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $RuleName,

        # RuleSet of the Firewall rule in which the rule shall be edited
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("WAN_IN","WAN_OUT","WAN_LOCAL","LAN_IN","LAN_OUT","LAN_LOCAL","GUEST_IN","GUEST_OUT","GUEST_LOCAL")]
        [string]
        $RuleSet,

        # Action of the Firewall rule
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("Drop","Reject","Accept")]
        [string]
        $Action,

        # State of the Firewall rule
        [Parameter(
            Mandatory = $false
        )]
        [Alias("State")]
        [bool]
        $Enabled,

        # Protocol of the Firewall rule
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("all","tcp","udp","tcp_udp","icmp")] # Protocol can also be specified by an integer, but this is not implemented here yet
        [string]
        $Protocol,

        # Should be logged o a syslog server?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $Logging,

        # Match new Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateNew,

        # Match established Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateEstablished,

        # Match invalid Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateInvalid,

        # Match related Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateRelated,

        # Match IPSEC Packages?
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("","match-ipsec","none")]
        [string]
        $IPSEC,

        # Source Type
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("NETv4","ADDRv4")] # Netv4 = "Address/Port-Group" in WebUI, needs Parameter "SourceFirewallGroupID" or leave empty for no source filtering; ADDRv4 = "Network" or "IP Address" in WebUI
        [string]
        $SourceType,

        # Source Firewall Groups, must be used with $SourceType = NETv4
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $SourceFirewallGroupIDs,

        # Source Network ID, must be used with $SourceType = ADDRv4
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $SourceNetworkID,

        # Source Address, must be used with $SourceType = ADDRv4
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $SourceAddress,

        # Destination Type
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("NETv4","ADDRv4")] # Netv4 = "Address/Port-Group" in WebUI, needs Parameter "SourceFirewallGroupID" or leave empty for no source filtering; ADDRv4 = "Network" or "IP Address" in WebUI
        [string]
        $DestinationType,

        # Destination Firewall Groups, must be used with $DestinationType = NETv4
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $DestinationFirewallGroupIDs,

        # Destination Network ID, must be used with $DestinationType = ADDRv4
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $DestinationNetworkID,

        # Destination Address, must be used with $DestinationType = ADDRv4
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $DestinationAddress,

        # Rule Index, set to "append", "prepend" or any number
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $RuleIndex

        # missing parameters by now: icmp_typename, src_mac_address, dst_mac_address, setting_preference, protocol_match_excepted
    )

    process {
        try {
            $fwRule = Get-UnifiFirewallRule -SiteName $SiteName | Where-Object { $_.RuleID -eq $RuleID }

            if ($fwRule) {

                $Body = @{}
                # Only add parameters which were given to the Rest-Body
                if ($PSBoundParameters.ContainsKey('RuleName')) {
                    $Body.name = $RuleName
                }

                if ($PSBoundParameters.ContainsKey('RuleSet')) {
                    $Body.ruleset = $RuleSet
                }

                if ($PSBoundParameters.ContainsKey('Action')) {
                    $Body.action = $Action.ToLower()
                }

                if ($PSBoundParameters.ContainsKey('Enabled')) {
                    $Body.enabled = $Enabled
                }

                if ($PSBoundParameters.ContainsKey('Protocol')) {
                    $Body.protocol = $Protocol.ToLower()
                }

                if ($PSBoundParameters.ContainsKey('Logging')) {
                    $Body.logging = $Logging.IsPresent
                }

                if ($PSBoundParameters.ContainsKey('StateNew')) {
                    $Body.state_new = $StateNew.IsPresent
                }

                if ($PSBoundParameters.ContainsKey('StateEstablished')) {
                    $Body.state_established = $StateEstablished.IsPresent
                }

                if ($PSBoundParameters.ContainsKey('StateInvalid')) {
                    $Body.state_invalid = $StateInvalid.IsPresent
                }

                if ($PSBoundParameters.ContainsKey('StateRelated')) {
                    $Body.state_related = $StateRelated.IsPresent
                }

                if ($PSBoundParameters.ContainsKey('IPSEC')) {
                    $Body.ipsec = $IPSEC
                }

                if ($PSBoundParameters.ContainsKey('SourceType')) {
                    $Body.src_networkconf_type = $SourceType
                }

                if ($PSBoundParameters.ContainsKey('SourceFirewallGroupIDs')) {
                    $Body.src_firewallgroup_ids = $SourceFirewallGroupIDs
                }

                if ($PSBoundParameters.ContainsKey('SourceNetworkID')) {
                    $Body.src_networkconf_id = $SourceNetworkID
                }

                if ($PSBoundParameters.ContainsKey('SourceAddress')) {
                    $Body.src_address = $SourceAddress
                }

                if ($PSBoundParameters.ContainsKey('DestinationType')) {
                    $Body.dst_networkconf_type = $DestinationType
                }

                if ($PSBoundParameters.ContainsKey('DestinationFirewallGroupIDs')) {
                    $Body.dst_firewallgroup_ids = $DestinationFirewallGroupIDs
                }

                if ($PSBoundParameters.ContainsKey('DestinationNetworkID')) {
                    $Body.dst_networkconf_id = $DestinationNetworkID
                }

                if ($PSBoundParameters.ContainsKey('DestinationAddress')) {
                    $Body.dst_address = $DestinationAddress
                }

                if ($PSBoundParameters.ContainsKey('RuleIndex')) {
                    $Body.rule_index = $RuleIndex
                }

                $Body = $Body | ConvertTo-Json

                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($SiteName)/rest/firewallrule/$($fwRule.RuleID)" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall rule '$($fwRule.RuleName)' successfully edited for site '$SiteName'"

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
                } else {
                    Write-Error "Firewall rule '$($fwRule.RuleName)' was NOT edited for site '$SiteName' -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No Firewall rule with ID '$($fwRule.RuleID)' in site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while editing firewall rule with ID '$($fwRule.RuleID)' for site '$SiteName' ($_)"
        }
    }
}
