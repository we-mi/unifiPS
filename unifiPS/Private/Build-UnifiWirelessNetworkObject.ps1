function Build-UnifiWirelessNetworkObject {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Object]
        $RawInput
    )

    process {
        $RawInput | Select-Object @{N="SiteName";E={$SiteName}},
                                @{N="SiteID";E={$_.site_id}},
                                Enabled,
                                wlan_bands,
                                @{N="SSID";E={$_.name}},
                                @{N="Passphrase";E={ if($ShowPassphrase.IsPresent) { $_.x_passphrase } else { "<PSK_IS_HIDDEN>"} }},
                                @{N="GuestNetwork";E={$_.is_guest}},
                                networkconf_id,
                                WPA3_Support,
                                WPA3_Transition,
                                Security,
                                wep_idx,
                                WPA_Mode,
                                WPA_Enc,
                                PMF_Mode,
                                PMF_Cipher,
                                usergroup_id,
                                WLAN_Band,
                                ap_group_ids,
                                dtim_mode,
                                dtim_ng,
                                dtim_na,
                                country_beacon,
                                minrate_ng_enabled,
                                minrate_ng_advertising_rates,
                                minrate_ng_data_rate_kbps,
                                minrate_na_enabled,
                                minrate_na_advertising_rates,
                                minrate_na_data_rate_kbps,
                                MAC_filter_enabled,
                                MAC_filter_Policy,
                                MAC_filter_list,
                                bc_filter_enabled,
                                bc_filter_list,
                                group_rekey,
                                hotspot2conf_enabled,
                                bss_transition,
                                auth_cache,
                                schedule_enabled,
                                setting_preference,
                                minrate_setting_preference,
                                radius_das_enabled,
                                iapp_enabled,
                                x_iapp_key,
                                dtim_6e
    }
}
