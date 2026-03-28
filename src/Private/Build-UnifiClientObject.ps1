function Build-UnifiClientObject {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Object]
        $RawInput
    )

    process {
        $RawInput | Select-Object @{N="SiteName";E={$SiteName}},
                                @{N="SiteID";E={$_.site_id}},
                                Adopted,
                                @{N="InformIP";E={$_.inform_ip}},
                                @{N="InformURL";E={$_.inform_url}},
                                IP,
                                MAC,
                                Model,
                                @{N="Name";E={ if (!$_.name){ $_.MAC}else{$_.name} }},
                                Serial,
                                Version,
                                @{N="State";E={
                                    $devicedata = $_
                                    switch($_.state) {
                                        0 { "Disconnected" }
                                        1 { "Connected" }
                                        2 { "Pending adoption"}
                                        4 {
                                            switch ($devicedata.upgrade_state) {
                                                3 { "Updating (Downloading)" }
                                                5 { "Updating (Writing)" }
                                                default { "Updating" }
                                            }
                                        }
                                        5 { "Provisioning" }
                                        7 { "Adopting" }
                                        default { $devicedata.state }
                                    }
                                }},
                                @{N="Connected";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.connected_at) }},
                                @{N="Provisioned";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.provisioned_at) }},
                                @{N="LastSeen";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.last_seen) }},
                                @{N="Uptime";E={ [Timespan]::FromSeconds($_.Uptime).ToString() }},
                                @{N="Startup";E={ (Get-Date("1970-01-01 00:00:00")).AddSeconds($_.startup_timestamp) }},
                                @{N="UpdateAvailable";E={ $_.upgradable }},
                                @{N="UpdateableFirmware";E={ $_.upgrade_to_firmware }},
                                @{N="Load1";E={ $_.sys_stats.loadavg_1 }},
                                @{N="Load5";E={ $_.sys_stats.loadavg_5 }},
                                @{N="Load15";E={ $_.sys_stats.loadavg_15 }},
                                @{N="CPUUsed";E={ $_."system-stats".cpu }},
                                @{N="MemUsed";E={ $_."system-stats".mem }}
    }
}
