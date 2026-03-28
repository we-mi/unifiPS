function Get-UnifiSiteInfo {
    <#
    .SYNOPSIS
        Gets extended information for a Unifi site
    .DESCRIPTION
        Gets extended information for a Unifi site like status for
        wlan (status, # APs, # adopted, # disabled, # disconnected, # pending, # users, # guests)
        wan (status, # adopted, # pending, # gateways)
        www (status, )
        lan (status, # adopted, #disconnected, # pending, # sw(?))
        vpn (status).

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSiteInfo -SiteName default
        Gets information from the default site
    .EXAMPLE
        PS C:\> Get-UnifiSite * | Get-UnifiSiteInfo
        Gets information from all sites
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
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/stat/health"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Raw) {
                    $jsonResult.data
                } else {
                    foreach ($subsystem in $jsonResult.data) {
                        switch ($subsystem.subsystem) {
                            "wlan" {
                                $subsystem | Select-Object  @{N="SiteName";E={$SiteName}},
                                                            Subsystem, Status,
                                                            @{N="APs";E={$_.num_ap}},
                                                            @{N="Adopted";E={$_.num_adopted}},
                                                            @{N="Disabled";E={$_.num_disabled}},
                                                            @{N="Disconnected";E={$_.num_disconnected}},
                                                            @{N="Pending";E={$_.num_pending}},
                                                            @{N="Users";E={$_.num_user}},
                                                            @{N="Guests";E={$_.num_guest}},
                                                            @{N="IOT";E={$_.num_iot}},
                                                            @{N="TX";E={$_."tx_bytes-r"}},
                                                            @{N="RX";E={$_."rx_bytes-r"}}
                            }

                            "wan" {
                                $subsystem | Select-Object  @{N="SiteName";E={$SiteName}},
                                                            Subsystem, Status,
                                                            @{N="Gateways";E={$_.num_gw}},
                                                            @{N="Adopted";E={$_.num_adopted}},
                                                            @{N="Disconnected";E={$_.num_disconnected}},
                                                            @{N="Pending";E={$_.num_pending}},
                                                            @{N="IP";E={$_.wan_ip}},
                                                            @{N="Gateway";E={$_.gateways}},
                                                            @{N="Netmask";E={$_.netmask}},
                                                            @{N="Nameservers";E={$_.nameservers}},
                                                            @{N="MAC";E={$_.gw_mac}},
                                                            @{N="Name";E={$_.gw_name}},
                                                            @{N="Version";E={$_.gw_version}},
                                                            @{N="Uptime";E={$_.uptime_stats}},
                                                            @{N="Stats";E={$_.'gw_system-stats'}},
                                                            @{N="TX";E={$_."tx_bytes-r"}},
                                                            @{N="RX";E={$_."rx_bytes-r"}},
                                                            @{N="STA";E={$_."num_sta"}}
                            }

                            "www" {
                                $subsystem | Select-Object  @{N="SiteName";E={$SiteName}},
                                                            Subsystem, Status,
                                                            @{N="TX";E={$_."tx_bytes-r"}},
                                                            @{N="RX";E={$_."rx_bytes-r"}},
                                                            @{N="Latency";E={$_.latency}},
                                                            @{N="Uptime";E={$_.Uptime}},
                                                            @{N="Drops";E={$_.Drops}},
                                                            @{N="Up";E={$_.xput_up}},
                                                            @{N="Down";E={$_.xput_down}},
                                                            @{N="SpeedtestStatus";E={$_.speedtest_status}},
                                                            @{N="SpeedtestLastRun";E={$_.speedtest_lastrun}},
                                                            @{N="SpeedtestPing";E={$_.speedtest_ping}},
                                                            @{N="MAC";E={$_.gw_mac}}
                            }

                            "lan" {
                                $subsystem | Select-Object  @{N="SiteName";E={$SiteName}},
                                                            Subsystem, Status,
                                                            @{N="Users";E={$_.num_user}},
                                                            @{N="Guests";E={$_.num_guest}},
                                                            @{N="IOT";E={$_.num_iot}},
                                                            @{N="TX";E={$_."tx_bytes-r"}},
                                                            @{N="RX";E={$_."rx_bytes-r"}},
                                                            @{N="Switche";E={$_.num_sw}},
                                                            @{N="Adopted";E={$_.num_adopted}},
                                                            @{N="Disconnected";E={$_.num_disconnected}},
                                                            @{N="Pending";E={$_.num_pending}}
                            }

                            "vpn" {
                                $subsystem | Select-Object  @{N="SiteName";E={$SiteName}},
                                                            Subsystem, Status
                            }
                        }
                    }

                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }

    }
}
