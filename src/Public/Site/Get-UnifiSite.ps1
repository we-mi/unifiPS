function Get-UnifiSite {
    <#
    .SYNOPSIS
        Lists sites of a unifi controller
    .DESCRIPTION
        Lists sites of a unifi controller. You can filter by ID, internal name and display name
        You can extend the output by displaying statistics and settings for each site but keep in mind that this behaviour will send more api-requests to the controller and might be slower in some cases.
    .NOTES
        You almost never come in touch with the ID of the site.
        The "InternalName" is what you need to talk to the api and it's also displayed in the url when the site is selected.
        "Name" is what you will see as the actual name of the site (internally handled as the site description)
    .EXAMPLE
        PS C:\> Get-UnifiSite
        List all sites
    .EXAMPLE
        PS C:\> Get-UnifiSite Stats
        List all sites and also display statistics for each site
    .EXAMPLE
        PS C:\> Get-UnifiSite -Name "Default","*Test*" -Settings
        Lists the site "default" and all sites which contain "Test" in the display name of the site and also display their settings
    .EXAMPLE
        PS C:\> Get-UnifiSite -InternalName "67itznop"
        Lists the site with the internal name '67itznop'
    .EXAMPLE
        PS C:\> Get-UnifiSite -ID "623e1bf66a5d4f1280160b7e"
        Lists the site with the ID '623e1bf66a5d4f1280160b7e'
    .OUTPUTS
        Returns objects of type 'Unifi.Site'
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    [OutputType([Unifi.Site])]

    param(
        [Parameter(ParameterSetName="ID")]
        [String[]]$ID,

        # Used for most API Calls
        [Parameter(ParameterSetName="InternalName")]
        [String[]]$InternalName,

        # internally handled as "description"
        [Parameter(ParameterSetName="Name",Position=0)]
        [String[]]$Name = @("*"),

        [Parameter()]
        [switch]$Stats,

        [Parameter()]
        [switch]$Settings

    )

    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "self/sites"

        switch ($PSCmdlet.ParameterSetName) {
            "ID" {
                $tmpList = @()
                foreach($entity in $ID) {
                    $tmpList += $jsonResult | Where-Object { $_._id -like $entity }
                }
                $jsonResult = $tmpList | Sort-Object -Property _id -Unique
            }

            "InternalName" {
                $tmpList = @()
                foreach($entity in $InternalName) {
                    $tmpList += $jsonResult | Where-Object { $_.name -like $entity }
                }
                $jsonResult = $tmpList | Sort-Object -Property _id -Unique
            }

            "Name" {
                $tmpList = @()
                foreach($entity in $Name) {
                    $tmpList += $jsonResult | Where-Object { $_.desc -like $entity }
                }
                $jsonResult = $tmpList | Sort-Object -Property _id -Unique
            }
        }

        if ($Stats) {
            # lets make another api call and read stat info
            $statResult = Invoke-UnifiRestCall -Method GET -Route "stat/sites"

            foreach ($site in $jsonResult) {
                $StatsForSite = $statResult | Where-Object { $_._id -eq $site._id }
                $site | Add-Member -MemberType NoteProperty -Name health -Value $StatsForSite.health
            }
        }

        if ($Settings) {
            # lets make another api call and read settings. but this time it only works with one api call per site :> (thank you again unifi)

            foreach ($site in $jsonResult) {
                $settingResult = Invoke-UnifiRestCall -Method GET -Route ("s/{0}/get/setting" -f $site.name) | Where-Object { $_.key -notlike "*super*" }

                $settingsHash = @{}
                switch ($settingResult.key) {
                    "mgmt" {
                        $key = $settingResult | Where-Object { $_.key -eq "mgmt" }
                        $settingsHash.mgmt = @{
                            WifiManEnabled = $key.wifiman_enabled
                            SSHPasswordLogin = $key.x_ssh_auth_password_enabled
                            SSHUsername = $key.x_ssh_username
                            SSHPassword = $key.x_ssh_password
                            SSHKeys = $key.x_ssh_keys
                            IDPEnabled = $key.unifi_idp_enabled
                            DebugToolsEnabled = $key.debug_tools_enabled
                            AutoUpgradeEnabled = $key.auto_upgrade
                            AutoUpgradeHour = $key.auto_upgrade_hour
                        }
                    }

                    "ntp" {
                        $key = $settingResult | Where-Object { $_.key -eq "ntp" }
                        $settingsHash.ntp = @{
                            Mode = $key.setting_preference
                            Server1 = $key.ntp_server_1
                            Server2 = $key.ntp_server_2
                            Server3 = $key.ntp_server_3
                            Server4 = $key.ntp_server_4
                        }
                    }

                    "dpi" {
                        $key = $settingResult | Where-Object { $_.key -eq "dpi" }
                        $settingsHash.dpi = @{
                            Enabled = $key.enabled
                            FingerprintingEnabled = $key.fingerprintingEnabled
                        }
                    }

                    "lcm" {
                        $key = $settingResult | Where-Object { $_.key -eq "lcm" }
                        $settingsHash.lcm = @{
                            Enabled = $key.enabled
                            Sync = $key.sync
                            IdleTimeout = $key.idle_timeout
                            TouchEvent = $key.touch_event
                            Brightness = $key.brightness
                        }
                    }

                    "rsyslogd" {
                        $key = $settingResult | Where-Object { $_.key -eq "rsyslogd" }
                        $settingsHash.rsyslogd = @{
                            Enabled = $key.enabled
                            ThisController = $key.this_controller
                            LogAllContents = $key.log_all_contents
                            ThisControllerEncryptedOnly = $key.this_controller_encrypted_only
                        }
                    }

                    "locale" {
                        $key = $settingResult | Where-Object { $_.key -eq "locale" }
                        $settingsHash.locale = @{
                            Timezone = $key.Timezone
                        }
                    }

                    "country" {
                        $key = $settingResult | Where-Object { $_.key -eq "country" }
                        $settingsHash.country = @{
                            Code = $key.Code
                        }
                    }
                }

                $site | Add-Member -MemberType NoteProperty -Name settings -Value $settingsHash
            }
        }

        foreach ($site in $jsonResult) {
            [Unifi.Site]::new($site)
        }
    }
}
