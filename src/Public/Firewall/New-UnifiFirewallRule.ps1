function New-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Creates a new firewall rule for a site
    .DESCRIPTION
        Creates a new firewall rule for a site
    .EXAMPLE
        PS C:\> $RDPGroup = Get-UnifiSite "default" | Get-UnifiFirewallGroup | Where-Object { $_.GroupName -eq "RDP-Ports" }
        PS C:\> Get-UnifiSite "default" | New-UnifiFirewallRule -RuleName "Allow RDP-Traffic" -RuleSet WAN_IN -Action Accept -Enabled $True -Protocol tcp_udp -DestinationFirewallGroupIDs $RDPGroup.GroupID
        Allow RDP-Traffic in default site for ruleset WAN_IN
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

        # ID of the site
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteID,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw,

        # Name of the Firewall rule to be created
        [Parameter(
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $RuleName,

        # RuleSet of the Firewall rule in which the rule shall be created
        [Parameter(
            Mandatory = $true
        )]
        [ValidateSet("WAN_IN","WAN_OUT","WAN_LOCAL","LAN_IN","LAN_OUT","LAN_LOCAL","GUEST_IN","GUEST_OUT","GUEST_LOCAL")]
        [string]
        $RuleSet,

        # Action of the Firewall rule
        [Parameter(
            Mandatory = $true
        )]
        [ValidateSet("Drop","Reject","Accept")]
        [string]
        $Action,

        # State of the Firewall rule
        [Parameter(
            Mandatory = $true
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
        $Protocol = "all",

        # Should be logged to a syslog server?
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
        $StateNew = $false,

        # Match established Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateEstablished = $false,

        # Match invalid Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateInvalid = $false,

        # Match related Packages?
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $StateRelated = $false,

        # Match IPSEC Packages?
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("","match-ipsec","none")]
        [string]
        $IPSEC = "",

        # Source Type
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("NETv4","ADDRv4")] # Netv4 = "Address/Port-Group" in WebUI, needs Parameter "SourceFirewallGroupID" or leave empty for no source filtering; ADDRv4 = "Network" or "IP Address" in WebUI
        [string]
        $SourceType = "NETv4",

        # Source Firewall Groups, must be used with $SourceType = NETv4
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $SourceFirewallGroupIDs = @(),

        # Source Network ID, must be used with $SourceType = ADDRv4
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $SourceNetworkID = "",

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
        $DestinationType = "NETv4",

        # Destination Firewall Groups, must be used with $DestinationType = NETv4
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $DestinationFirewallGroupIDs = @(),

        # Destination Network ID, must be used with $DestinationType = ADDRv4
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $DestinationNetworkID = "",

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
        $RuleIndex = "append"

        # missing parameters by now: icmp_typename, src_mac_address, dst_mac_address, setting_preference, protocol_match_excepted

    )

    process {

        if ($RuleIndex -eq "append" -or $RuleIndex -eq "prepend") {
            # Get all current firewall rules for this $RuleSet to calculate the new RuleIndex
            $curRules = Get-UnifiFirewallRule -siteName $SiteName | Where-Object { $_.RuleSet -eq $RuleSet } | Sort-Object -Property RuleIndex

            if ($curRules.Count -eq 0) {
                $RuleIndexNr = 2000
            } elseif ($RuleIndex -eq "append") {
                $RuleIndexNr = ($CurRules | Select-Object -Last 1 -ExpandProperty RuleIndex) + 1
            } elseif ($RuleIndex -eq "prepend") {
                $RuleIndexNr = ($CurRules | Select-Object First 1 -ExpandProperty RuleIndex) - 1
            }
        } else {
            $RuleIndexNr = $RuleIndex
        }

        if ($RuleIndexNr -le 0) {
            Write-Error "Firewall Rule Index can't be zero or negative"
            return ""
        }

        try {
            $Body = @{
                action                  = $Action.ToLower()
                dst_address             = $DestinationAddress           # only when $DestinationType -eq ADDRv4
                dst_firewallgroup_ids   = $DestinationFirewallGroupIDs  # only when $DestinationType -eq NETv4
                dst_networkconf_id      = $DestinationNetworkID        # only when $DestinationType -eq ADDRv4
                dst_networkconf_type    = $DestinationType
                enabled                 = $Enabled
                icmp_typename           = ""
                ipsec                   = $IPSEC
                logging                 = $Logging.IsPresent
                name                    = $RuleName
                protocol                = $Protocol.ToLower()
                protocol_match_excepted = $False
                rule_index              = $RuleIndexNr
                ruleset                 = $RuleSet
                src_address             = $SourceAddress                # only when $DestinationType -eq ADDRv4
                src_firewallgroup_ids   = $SourceFirewallGroupIDs       # only when $DestinationType -eq NETv4
                src_mac_address         = ""
                src_networkconf_id      = $SourceNetworkID             # only when $DestinationType -eq ADDRv4
                src_networkconf_type    = $SourceType
                state_established       = $StateEstablished.IsPresent
                state_invalid           = $StateInvalid.IsPresent
                state_new               = $StateNew.IsPresent
                state_related           = $StateRelated.IsPresent
                site_id                 = $SiteID
                setting_preference      = "manual"
            } | ConvertTo-Json

            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/rest/firewallrule" -Body $Body

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Firewall rule '$RuleName' successfully created for site $SiteName"

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
                Write-Error "Firewall rule '$RuleName' was NOT created for site '$SiteName'"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall rule for site $($SiteName) ($_)"
        }
    }
}
