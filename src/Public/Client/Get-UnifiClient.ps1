function Get-UnifiClient {
    <#
    .SYNOPSIS
        Gets Unifi Clients (Users, Guests)
    .DESCRIPTION
        Gets Unifi Clients (Users, Guests)

        You can pipe the output from "Get-UnifiSite" to this cmdlet

        This function lists all known clients by default. If you wish to only show active (currently connected) clients/users use the $Active-Switch

        THe output of Active clients differs from the output of all clients.
    .EXAMPLE
        PS C:\> Get-UnifiClient -SiteName "default"
        Returns all clients from site "default"
    .EXAMPLE
        PS C:\> Get-UnifiClient -SiteName "default" -Active
        Returns all currently connected clients from site "default"
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
        $Raw,

        # Only list active clients and show additional info for them
        [Parameter(Mandatory = $false)]
        [switch]
        $Active
    )

    process {
        try {
            if ($Active) {
                $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/stat/sta"

                if ($jsonResult.meta.rc -eq "ok") {

                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                            @{N="SiteID";E={$_.site_id}},
                                                            MAC,
                                                            @{N="IPAddress";E={$_.ip}},
                                                            VLAN,
                                                            @{N="Username";E={$_."1x_identity"}},
                                                            Hostname,
                                                            @{N="Manufacturer";E={$_.oui}},
                                                            @{N="Guest";E={$_.is_guest}},
                                                            @{N="Wired";E={$_.is_wired}},
                                                            @{N="SSID";E={$_.essid}},
                                                            @{N="BSSID";E={$_.bssid}},
                                                            @{N="AccessPointMAC";E={$_.ap_mac}},
                                                            Channel,
                                                            Radio,
                                                            Signal,
                                                            Noise,
                                                            RSSI,
                                                            @{N="TXRate";E={ "$($_.tx_rate / 1000) Mbps"}},
                                                            @{N="RXRate";E={ "$($_.rx_rate / 1000) Mbps" }},
                                                            @{N="TXPower";E={$_.tx_power}},
                                                            @{N="WifiTX";E={ "$($_.tx_bytes / 1048576) MB" }},
                                                            @{N="WifiRX";E={ "$($_.rx_bytes / 1048576) MB" }},
                                                            @{N="WiredTX";E={ "$($_.wired_tx_bytes / 1048576) MB" }},
                                                            @{N="WiredRX";E={ "$($_.wired_rx_bytes / 1048576) MB" }},
                                                            @{N="TXAttempts";E={$_.wifi_tx_attempts}},
                                                            @{N="TXRetries";E={$_.tx_retries}},
                                                            Authorized,
                                                            @{N="Uptime";E={ [Timespan]::FromSeconds($_.Uptime).ToString() }},
                                                            @{N="FirstSeen";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.first_seen) }},
                                                            @{N="LastSeen";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.last_seen) }},
                                                            @{N="Disconnected";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.disconnect_timestamp) }},
                                                            @{N="Associated";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.assoc_time) }},
                                                            @{N="AssociatedLatest";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.latest_assoc_time) }}
                    }
                }
            } else {
                $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/user"

                if ($jsonResult.meta.rc -eq "ok") {

                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                            @{N="SiteID";E={$_.site_id}},
                                                            MAC,
                                                            @{N="Manufacturer";E={$_.oui}},
                                                            @{N="Guest";E={$_.is_guest}},
                                                            @{N="Wired";E={$_.is_wired}},
                                                            @{N="FirstSeen";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.first_seen) }},
                                                            @{N="LastSeen";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.last_seen) }},
                                                            @{N="Disconnected";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.disconnect_timestamp) }}
                    }
                }
            }
        } catch {
            Write-Error "Something went wrong while fetching clients ($($_.Exception))"
        }
    }
}
