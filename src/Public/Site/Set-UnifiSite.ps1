function Set-UnifiSite {
    <#
    .SYNOPSIS
        Create a new unifi site
    .DESCRIPTION
        Create a new unifi site
    .EXAMPLE
        PS C:\> New-UnifiSite -Name superior_site
        Will create a new site with the name "superior_site"
    .OUTPUTS
        Returns 'Unifi.Site'-Object when '-PassThru' is set, else nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([Unifi.Site] -or $null)]

    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="String")]
        [String]$SiteName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="Object")]
        [Unifi.Site]$SiteObject,

        [Parameter()]
        [String]$NewName,

        [Parameter()]
        [String]$Country,

        [Parameter()]
        [String]$Timezone,

        [Parameter()]
        [ValidateCount(1,4)]
        [String[]]$NTPServers,

        [Parameter()]
        [Switch]$AutoUpgrade,

        [Parameter()]
        [ValidateRange(0,24)]
        [Byte]$AutoUpgradeHour,

        [Parameter()]
        [Switch]$EnableSSH,

        [Parameter()]
        [Switch]$EnableSSHPasswordLogin,

        [Parameter()]
        [String]$SSHUser,

        [Parameter()]
        [SecureString]$SSHPassword,

        [Parameter()]
        [Hashtable[]]$SSHKeys, # array of @{name = ..., key = ...}

        [Parameter()]
        [Switch]$EnableWifiMan,

        [Parameter()]
        [Switch]$EnableDebugMode,

        [Parameter()]
        [Switch]$EnableIDP,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        # Get a list of all sites or just us before we do anything
        $allSites = Get-UnifiSite
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq "String") {
            # we only got a sitename. Get the Unifi-Object of it
            $SiteObject = $allSites | Where-Object { $_.Name -eq $SiteName }
        }

        $Method = "POST"
        $Route = "s/{0}/cmd/sitemgr" -f $SiteObject.InternalName # Creating a site requires to use a site api endpoint (why though unifi??). We use the default site here, because it's already there and cannot be deleted

        $Body = @{
            cmd = "update-site"
        }

        if ( -not [String]::IsNullOrWhiteSpace($NewName) ) {
            $Body.desc = $NewName
        }

        if ( $PSCmdlet.ShouldProcess($SiteObject.Name, "Update unifi site") ) {
            $jsonResult = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)

            # Some settings cant be controlled through sitemgr api call. They have their own api call (thank you unifi)

            if ( -not [String]::IsNullOrWhiteSpace($Country) ) {
                $Route = "s/{0}/set/setting/country" -f $SiteObject.InternalName
                $Body = @{
                    key = "country"
                    code = $Country
                }

                $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }

            if ( -not [String]::IsNullOrWhiteSpace($Timezone) ) {
                $Route = "s/{0}/set/setting/locale" -f $SiteObject.InternalName
                $Body = @{
                    key = "locale"
                    timezone = $Timezone
                }

                $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }

            if ( -not [String]::IsNullOrEmpty($NTPServers) ) {
                $Route = "s/{0}/set/setting/ntp" -f $SiteObject.InternalName

                if ( $NTPServers.Count -eq 1 -and $NTPServers[0] -eq "auto") {
                    $Body = @{
                        key = "ntp"
                        ntp_server_1 = "0.ubnt.pool.ntp.org"
                        ntp_server_2 = "1.ubnt.pool.ntp.org"
                        ntp_server_3 = "2.ubnt.pool.ntp.org"
                        ntp_server_4 = "3.ubnt.pool.ntp.org"
                        setting_preference = "auto"
                    }
                } else {
                    $Body = @{
                        key = "ntp"
                        ntp_server_1 = $( if ([String]::IsNullOrWhitespace($NTPServers[0]) ) { "" } else { $NTPServers[0]} )
                        ntp_server_2 = $( if ([String]::IsNullOrWhitespace($NTPServers[1]) ) { "" } else { $NTPServers[1]} )
                        ntp_server_3 = $( if ([String]::IsNullOrWhitespace($NTPServers[2]) ) { "" } else { $NTPServers[2]} )
                        ntp_server_4 = $( if ([String]::IsNullOrWhitespace($NTPServers[3]) ) { "" } else { $NTPServers[3]} )
                        setting_preference = "manual"
                    }
                }


                $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }

            if ($PSBoundParameters.Keys -match "AutoUpgrade|AutoUpgradeHour|EnableSSH|EnableSSHPasswordLogin|SSHUser|SSHPassword|EnableWifiMan|EnableAdvancedFeatures|EnableDebugMode|EnableIDP|SSHKeys") {
                $Route = "s/{0}/set/setting/mgmt" -f $SiteObject.InternalName
                $Body = @{
                    key = "mgmt"
                }

                switch ($test.Keys) {
                    "AutoUpgrade" {
                        $Body.auto_upgrade = $AutoUpgrade.IsPresent
                    }
                    "AutoUpgradeHour" {
                        $Body.auto_upgrade_hour = $AutoUpgradeHour
                    }
                    "EnableSSH" {
                        $Body.x_ssh_enabled = $EnableSSH.IsPresent
                    }
                    "EnableSSHPasswordLogin" {
                        $Body.x_ssh_auth_password_enabled = $EnableSSHPasswordLogin.IsPresent
                    }
                    "SSHUser" {
                        $Body.x_ssh_username = $SSHUser
                    }
                    "SSHPassword" {
                        $Body.x_ssh_password = [System.Management.Automation.PSCredential]::new("dummy",$SSHPassword).GetNetworkCredential().Password
                    }
                    "EnableWifiMan" {
                        $Body.wifiman_enabled = $EnableWifiMan.IsPresent
                    }
                    "EnableDebugMode" {
                        $Body.debug_tools_enabled = $EnableDebugMode.IsPresent
                    }
                    "EnableIDP" {
                        $Body.unifi_idp_enabled = $EnableIDP.IsPresent
                    }
                    "SSHKeys" {
                        $keys = New-Object System.Collections.ArrayList

                        foreach ($sshKey in $SSHKeys) {
                            if ($sshKey.Key -match '^(?<type>ssh-.*) (?<key>.*) (?<comment>.*)$') {
                                $keys.Add(@{
                                    type = $Matches.type
                                    name = $sshKey.name
                                    comment = $Matches.comment
                                    key = $Matches.key
                                })
                            } else {
                                throw "Invalid SSH-Key"
                            }
                        }
                        $Body.x_ssh_keys = $keys
                    }
                }

                $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }
        }

        if ($PassThru) {
            [Unifi.Site]::new($jsonResult)
        }
    }
}
