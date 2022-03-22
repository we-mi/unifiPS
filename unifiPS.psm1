$Script:WebSession = $null
$Script:BaseUri = $null
$Script:RestHeaders = $null

function Invoke-UnifiRestCall {
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # HTTP Method
        [Parameter(Mandatory = $True)]
        [ValidateSet("GET","POST","PUT","DELETE")]
        [string]
        $Method,

        # REST route
        [Parameter(Mandatory = $True)]
        [string]
        $Route,

        # Rest Body
        [Parameter(Mandatory = $False)]
        [Object]
        $Body,

        # Rest Body
        [Parameter(Mandatory = $False)]
        [Object]
        $CustomRestParams
    )

    process {
        $restParams = @{
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = $script:Timeout
            Uri = $($script:BaseUri) + "/" + $Route
            WebSession = $Script:WebSession
            Method = $Method
            Verbose = $false
        }

        if ($CustomRestParams) {
            $restParams = $CustomRestParams
        }

        if (@("POST","PUT","DELETE") -contains $Method) {
            $restParams.Body = $Body
        }

        Write-Verbose "Calling $($restParams.Uri) [$($restParams.Method)]"
        try {
            $json = Invoke-RestMethod @restParams
        } catch [System.Net.WebException] {
            $json = $_.ErrorDetails | ConvertFrom-Json
            $ErrorCode = $json.meta.msg
            Write-Error "Error while accessing rest endpoint '$Route' ($Method): $ErrorCode"
        } catch {
            Write-Error "Other error while accessing rest endpoint '$Route' ($Method): $_"
        } finally {
            if ($json) {
                $json
            }

            if ($restParams.SessionVariable) {
                $script:WebSession = $WebSession
            }
        }

    }
}

function Invoke-UnifiLogin {
    <#
    .SYNOPSIS
        Makes a RestMethod request to the unifi api, which will hopefully login the given user
    .DESCRIPTION
        Makes a RestMethod request to the unifi api, which will hopefully login the given user
        Credentials can be directly used with $Credentials-Parameter (you will be asked for credentials if this parameter is omitted).
        If the login succeeds a WebSession is saved to $Script:WebSession

        A timeout can be specified for the webrequest
    .EXAMPLE
        PS C:\> Invoke-UnifiLogin -Uri https://192.168.178.1:8443/api -Timeout 5
        Logs in to the unifi server at the specified address and wait max. 5 seconds
    #>
    [CmdletBinding()]

    param(
        # Uri of the UniFi Server
        [Parameter(
            Mandatory = $true
        )]
        [string]
        $Uri,

        # Login credentials
        [Parameter(
            Mandatory = $false
        )]
        [System.Management.Automation.PSCredential]
        $Credential,

        # Timeout in seconds
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Timeout= 5
    )

    process {
        $script:BaseUri = $Uri
        $script:Timeout = $Timeout
        $Script:WebSession = $null

        try {
            add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
        } catch {}

        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

        if (!($Credential)) {
            $Credential = (Get-Credential -Message "Login for UniFi-Controller $($script:BaseUri)")
        }
        $Body = @{ "username" = $Credential.UserName; "password" = $Credential.GetNetworkCredential().Password } | ConvertTo-JSON

        $restParams = @{
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = $script:Timeout
            Uri = $($script:BaseUri) + "/api/login"
            SessionVariable = "WebSession"
            Verbose = $false
            Method = "Post"
        }

        $jsonResult = Invoke-UnifiRestCall -Method POST -Route "login" -Body $Body -CustomRestParams $restParams

        $Credential = $null
        $Body = $null

        if ($jsonResult.meta.rc -eq "ok") {
            Write-Host -ForegroundColor Green "Login to Unifi-Controller successful"
        } else {
            Write-Host -ForegroundColor Red "Login to Unifi-Controller failed"
        }
    }
}

function Invoke-UnifiLogout {
    <#
    .SYNOPSIS
        Logs out of the unifi server and destroys the websession
    .DESCRIPTION
        Logs out of the unifi server and destroys the websession
    .EXAMPLE
        PS C:\> Invoke-UnifiLogout
        Logs out of the server
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param()

    begin {
    }

    process {
        $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/logout"

        if ($jsonResult.meta.rc -eq "ok") {
            Write-Host -ForegroundColor Green "Logout from Unifi-Controller successful"
        } else {
            Write-Host -ForegroundColor Red "Logout from Unifi-Controller failed"
        }
        
    }
}

function Get-UnifiServerInfo {
    <#
    .SYNOPSIS
        Grabs simple information from the unifi server (state,version,uuid)
    .DESCRIPTION
        Grabs simple information from the unifi server (state,version,uuid)
    .EXAMPLE
        PS C:\> Get-UnifiServerInfo
        Grabs the information
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )
   
    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "status"

        if ($jsonResult.meta.rc -eq "ok") {
            if ($Raw) {
                $jsonResult.meta
            } else {
                $jsonResult.meta | Select-Object UUID,@{N="Version";E={$_.server_version}},@{N="URI";E={$Script:BaseUri}}
            }
        }
    }
}

function Get-UnifiLogin {
    <#
    .SYNOPSIS
        Reads information about the currently logged in user
    .DESCRIPTION
        Reads information about the currently logged in user
    .EXAMPLE
        PS C:\> Get-UnifiLogin
        Reads the information
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/self"

        if ($jsonResult.meta.rc -eq "ok") {
            if ($Raw) {
                $jsonResult.data
            } else {
                $jsonResult.data | Select-Object Name,@{N="AdminID";E={$_.admin_id}},EMail,@{N="EMailAlert";E={$_.email_alert_enabled}},@{N="SuperAdmin";E={$_.is_super}},@{N="UISettings";E={$_.ui_settings}}
            }
        }
    }
}

function Get-UnifiSite {
    <#
    .SYNOPSIS
        Gets all sites of the unifi controller
    .DESCRIPTION
        Gets all sites of the unifi controller
        You can filter by name (internal site name) or id or DisplayName (name visible in the web interface, unifi's internal name for this field is 'desc')
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName *
        Lists all sites
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Default","*Test*"
        Lists all sites which contains the string "Test" and the site with the name "Default"
    #>
    [CmdletBinding(DefaultParameterSetName="SiteDisplayName")]
    [OutputType([Object])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter( ParameterSetName = "SiteName", Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String[]]
        $SiteName,

        # ID of the site
        [Parameter( ParameterSetName = "SiteID", Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String[]]
        $SiteID,

        # friendlyName of the site (Unifi's internal name for this field is 'desc'). This is the value visible in the web interface
        [Parameter( ParameterSetName = "SiteDisplayName", Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0 )]
        [Alias("SiteDescription")]
        [String[]]
        $SiteDisplayName,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )
   
    process {
        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/self/sites"

            if ($jsonResult.meta.rc -eq "ok") {

                switch ($PSCmdlet.ParameterSetName) {
                    "SiteName" { 
                        $tmpList = @()
                        foreach($singleSiteName in $SiteName) {
                            $tmpList += $jsonResult.data | Where-Object { $_.Name -like $singleSiteName }
                        }
                        $jsonResult.data = $tmpList
                    }
                    "SiteID" {
                        $tmpList = @()
                        foreach($singleSiteID in $SiteID) {
                            $tmpList += $jsonResult.data | Where-Object { $_._id -like $singleSiteID }
                        }
                        $jsonResult.data = $tmpList
                    }
                    "SiteDisplayName" { 
                        $tmpList = @()
                        foreach($singleSiteDisplayName in $SiteDisplayName) {
                            $tmpList += $jsonResult.data | Where-Object { $_.desc -like $singleSiteDisplayName }
                        }
                        $jsonResult.data = $tmpList
                    }
                }

                if ($Raw) {
                    $jsonResult.data 
                } else {
                    $jsonResult.data | Select-Object @{N="SiteID";E={$_._id}},@{N="SiteDisplayName";E={$_.desc}},@{N="SiteName";E={$_.name}},@{N="NoDelete";E={ if ($_.attr_no_delete) {$_.attr_no_delete} else { $False }}}
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
    }
}

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
        Each of this entries are returned as a single hashtable

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSiteInfo
        Gets information from all sites
    .EXAMPLE
        PS C:\> Get-UnifiSiteInfo -friendlyName "*Einhard*"
        Gets information from all sites which contains the string "Einhard"
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

function Get-UnifiAdmin {
    <#
    .SYNOPSIS
        Lists unifi admins for all or just one site
    .DESCRIPTION
        Lists unifi admins for all or just one site
    .EXAMPLE
        PS C:\> Get-UnifiAdmin -All
        Lists unifi admins for all sites
        
        PS C:\> Get-UnifiAdmin -SiteName "Default"
        Lists unifi admins for site "Default"
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw,

        # List Admins for all sites
        [Parameter(Mandatory = $false, ParameterSetName="All")]
        [switch]
        $All,

        # SiteName 
        [Parameter(Mandatory = $false, ParameterSetName="SiteName", ValueFromPipelineByPropertyName=$True)]
        [string]
        $SiteName
    )
   
    process {
        if (!$All -and [string]::IsNullOrWhiteSpace($SiteName)) {
            Write-Error "No SiteName was given"
        } else {
            if ($All) {
                $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/stat/admin"
            } else {
                $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body (@{cmd = "get-admins"} | ConvertTo-JSON)
            }

            if ($jsonResult.meta.rc -eq "ok") {
                if ($Raw) {
                    $jsonResult.data
                } else {
                    if ($All) {
                        $jsonResult.data | Select-Object    name,email,
                                                        @{N="UserID";E={$_._id}},
                                                        @{N="SuperAdmin";E={$_.is_super}},
                                                        @{N="Roles";E={$_.roles}},
                                                        @{N="SuperRoles";E={$_.super_roles}},
                                                        @{N="CreatedOn";E={ ( Get-Date('1970-01-01 00:00:00') ).AddSeconds($_.time_created) }},
                                                        @{N="LastSiteName";E={$_.last_site_name}},
                                                        @{N="EMailAlert";E={$_.email_alert_enabled}}
                    } else {
                        $jsonResult.data | Select-Object    name,email,
                                                        @{N="UserID";E={$_._id}},
                                                        @{N="Permissions";E={$_.permissions}},
                                                        @{N="SuperAdmin";E={$_.is_super}},
                                                        @{N="Role";E={$_.role}},
                                                        @{N="EMailAlert";E={$_.email_alert_enabled}}
                    }

                }
            }
        }
    }
}

function Get-UnifiEvent {
    <#
    .SYNOPSIS
        Gets events for a unifi site
    .DESCRIPTION
        Gets events for a unifi site

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Test" | Get-UnifiEvent
        Gets events from site with the DisplayName "Test"
    .EXAMPLE
        PS C:\> Get-UnifiEvent -SiteName "01gg6pt0"
        Gets events from the site with the (internal) name "01gg6pt0". If you want to use the display name for searching see the previous example
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

        # Limit the number of results as the output can be too big and slow. Zero means no limit
        [Parameter(Mandatory = $false)]
        [int16]
        $Limit = 500
    )
   
    process {
        
        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/stat/event"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Limit -gt 0) {
                    $jsonResult.data = $jsonResult.data | Select-Object -First $Limit
                }
                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object -ExcludeProperty "site_id","key","msg","_id","time","is_negative" @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="Category";E={$_.subsystem}},
                                                        @{N="Date";E={$_.DateTime}},
                                                        @{N="EventType";E={$_.key}},
                                                        @{N="Message";E={$_.msg}},
                                                        *
                    
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}

function Get-UnifiAlarm {
    <#
    .SYNOPSIS
        Gets alarms for a unifi site
    .DESCRIPTION
        Gets alarms for a unifi site

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Test" | Get-UnifiAlarm
        Gets alarms from site with the DisplayName "Test"
    .EXAMPLE
        PS C:\> Get-UnifiAlarm -SiteName "01gg6pt0"
        Gets alarms from the site with the (internal) name "01gg6pt0". If you want to use the display name for searching see the previous example
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

        # Limit the number of results as the output can be too big and slow. Zero means no limit
        [Parameter(Mandatory = $false)]
        [int16]
        $Limit = 500
    )
   
    process {
        
        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/stat/alarm"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Limit -gt 0) {
                    $jsonResult.data = $jsonResult.data | Select-Object -First $Limit
                }
                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object -ExcludeProperty "site_id","key","msg","_id","time","is_negative" @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="Category";E={$_.subsystem}},
                                                        @{N="Date";E={$_.DateTime}},
                                                        @{N="EventType";E={$_.key}},
                                                        @{N="Message";E={$_.msg}},
                                                        *
                    
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}

function Get-UnifiDevice {
    <#
    .SYNOPSIS
        Gets Unifi Devices (AP, Switch, Gateways, etc.)
    .DESCRIPTION
        Gets Unifi Devices (AP, Switch, Gateways, etc.).
        
        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiDevice -SiteName "default"
        Returns all devices from site "default"
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
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/stat/device"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        Adopted,
                                                        @{N="InformIP";E={$_.inform_ip}},
                                                        @{N="InformURL";E={$_.inform_url}},
                                                        IP,
                                                        MAC,
                                                        Model,
                                                        Name,
                                                        Serial,
                                                        Version,
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

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
    }
}

function Restart-UnifiDevice {
    <#
    .SYNOPSIS
        Restarts a unifi device
    .DESCRIPTION
        Restarts a unifi device

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "AP01" | Restart-UnifiDevice
        Restarts the device with the name "AP01" in site "Test"
    .EXAMPLE
        PS C:\> Restart-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55"
        Restarts the device with the mac "00:11:22:33:44:55" in site "Test"
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # MAC of the device to reconnect
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
   
    process {
        
        try {
            if (!$Force) {
                do {
                    $answer = Read-Host -Prompt "Do you really want to restart the device '$MAC'? (y/N): "
                } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                if ($answer -eq "" -or $answer -eq "n") {
                    Write-Verbose "Restart of device '$MAC' was aborted by user"
                    return $null
                }

            }
            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/devmgr" -Body (@{cmd = "restart"; mac = $MAC; reboot_type = "soft"} | ConvertTo-JSON)

            if ($jsonResult.meta.rc -eq "ok") {

                Write-Host -ForegroundColor Yellow "Device with '$MAC' will reboot now"
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}

function Sync-UnifiDevice {
    <#
    .SYNOPSIS
        Syncs a unifi device with the unifi controller (will force a provisioning)
    .DESCRIPTION
        Syncs a unifi device with the unifi controller (will force a provisioning)

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "AP01" | Sync-UnifiDevice
        Restarts the device with the name "AP01" in site "Test"
    .EXAMPLE
        PS C:\> Sync-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55"
        Restarts the device with the mac "00:11:22:33:44:55" in site "Test"
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # MAC of the device to sync
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )
   
    process {
        
        try {
            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/devmgr" -Body (@{cmd = "force-provision"; mac = $MAC} | ConvertTo-JSON)

            if ($jsonResult.meta.rc -eq "ok") {

                Write-Host -ForegroundColor Yellow "Device with '$MAC' will force a provision"
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}

function Get-UnifiClient {
    <#
    .SYNOPSIS
        Gets Unifi Clients (Users, Guests)
    .DESCRIPTION
        Gets Unifi Clients (Users, Guests)
        
        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiClient -SiteName "default"
        Returns all clients from site "default"
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
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
    }
}

function Disconnect-UnifiClient {
    <#
    .SYNOPSIS
        Disconnects a unifi client device (the client will try to reconnect)
    .DESCRIPTION
        Disconnects a unifi client device (the client will try to reconnect)

        You can pipe the output from "Get-UnifiClient" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "iPad01" | Disconnect-UnifiClient
        Restarts the client with the name "iPad01" in site "Test"
    .EXAMPLE
        PS C:\> Disconnect-UnifiClient -SiteName "Test" -MAC "00:11:22:33:44:55"
        Restarts the client with the mac "00:11:22:33:44:55" in site "Test"
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # MAC of the client to reconnect
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
   
    process {
        
        try {
            if (!$Force) {
                do {
                    $answer = Read-Host -Prompt "Do you really want to disconnect the client '$MAC'? (y/N): "
                } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                if ($answer -eq "" -or $answer -eq "n") {
                    Write-Verbose "Disconnecting the client '$MAC' was aborted by user"
                    return $null
                }

            }
            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/stamgr" -Body (@{cmd = "kick-sta"; mac = $MAC} | ConvertTo-JSON)

            if ($jsonResult.meta.rc -eq "ok") {

                Write-Host -ForegroundColor Yellow "Client '$MAC' was kicked"
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}

function Get-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Lists firewall groups in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Get-UnifiFirewallGroup TODO
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
        $Raw
    )
   
    process {
        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/firewallgroup"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="GroupID";E={$_._id}},
                                                        @{N="GroupName";E={$_.name}},
                                                        @{N="GroupMembers";E={$_.group_members}},
                                                        @{N="GroupType";E={$_.group_type}}

                }
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $($site.friendlyName) ($_)"
        }
        
    }
}

function New-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Creates a new firewall group in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> New-UnifiFirewallGroup TODO
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
                Write-Verbose "Firewall group $GroupName successfully created for site $SiteName"

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
                    Write-Warning "Firewall group $GroupName already exists in site ($SiteName)"
                } else {
                    Write-Error "Firewall group $GroupName was NOT created for site ($SiteName)"
                }
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $($site.friendlyName) ($_)"
        }
        
    }
}

function Edit-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Edits a firewall group in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Edit-UnifiFirewallGroup TODO
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
        $GroupID,

        # New name of the group. Leave empty to keep the name
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupName,

        # Group members (can be ipv4/ipv6 addresses or port numbers/ranges). Can also be empty. Will be overridden
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $GroupMembers = @()
    )
   
    process {
        
        try {
            $fwGroup = Get-UnifiFirewallGroup -SiteName $SiteName | Where-Object { $_.GroupID -eq $GroupID }

            if ($fwGroup) {

                # Use current name if no new name was given
                if ([String]::IsNullOrWhiteSpace($GroupName)) {
                    $GroupName = $fwGroup.GroupName
                }

                $Body = @{
                    '_id' = $fwGroup.GroupID
                    'site_id' = $fwGroup.SiteID
                    name = $GroupName
                    group_type = $fwGroup.GroupType
                    group_members = $GroupMembers
                } | ConvertTo-Json
                
                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/firewallgroup/$($fwGroup.GroupID)" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall group $GroupName successfully edited for site $SiteName"
                    
                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                            @{N="SiteID";E={$_.site_id}},
                                                            @{N="GroupID";E={$_._id}},
                                                            @{N="GroupName";E={$_.name}},
                                                            @{N="GroupMembers";E={$_.group_members}},
                                                            @{N="GroupType";E={$_.group_type}}
                    }
                } else {
                    Write-Error "Firewall group $GroupName was NOT edited for site $SiteName -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No Firewall Group with ID $GroupID in site $SiteName was found"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $SiteName ($_)"
        }
        
    }
}

function Remove-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Deletes a firewall group in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Remove-UnifiFirewallGroup TODO
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

        # ID of the Firewall group to be deleted
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupID,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
   
    process {
        try {
            $fwGroup = Get-UnifiFirewallGroup -SiteName $SiteName | Where-Object { $_.GroupID -eq $GroupID }

            if ($fwGroup) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the firewall group '$($fwGroup.GroupName)' (ID: $($GroupID))? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of firewall group '$($fwGroup.GroupName)' (ID: $($GroupID)) was aborted by user"
                        return $null
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/firewallgroup/$($GroupID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall group '$($fwGroup.GroupName)' successfully deleted for site $SiteName"
                } else {
                    Write-Error "Firewall group '$($fwGroup.GroupName)' was NOT deleted for site $SiteName"
                }
            } else {
                Write-Error "No Firewall Group with $GroupID was found in site $SiteName"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $($site.friendlyName) ($_)"
        }
        
    }
}

function Get-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Lists firewall rules in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Get-UnifiFirewallRule TODO
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
            Write-Warning "Something went wrong while creating a new firewall group for site $($SiteName) ($_)"
        }
        
    }
}

function New-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Creates a new firewall group in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> New-UnifiFirewallGroup TODO
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
                if ($jsonResult.meta.msg -eq "api.err.FirewallGroupExisted") {
                    Write-Warning "Firewall rule '$RuleName' already exists in site $SiteName"
                } else {
                    Write-Error "Firewall rule '$RuleName' was NOT created for site $SiteName"
                }
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $($site.friendlyName) ($_)"
        }
        
    }
}

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
        $Protocol = "all",

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
        Write-Warning "This cmdlet does not work at the moment due to 'invalidpayload' errors"
        try {
            $fwRule = Get-UnifiFirewallRule -SiteName $SiteName | Where-Object { $_.RuleID -eq $RuleID }

            if ($fwRule) {

                # Use current name if no new name was given
                if ([String]::IsNullOrWhiteSpace($RuleName)) {
                    $RuleName = $fwRule.RuleName
                }

                # Use current destination group IDs if no ones were given
                if ([String]::IsNullOrWhiteSpace($DestinationFirewallGroupIDs)) {
                    $DestinationFirewallGroupIDs = $fwRule.DstFirewallGroupIDs
                }

                $Body = @{
                    "_id"                   = $fwRule.RuleID
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
                    site_id                 = $fwRule.SiteID
                    setting_preference      = "manual"
                } | ConvertTo-Json
                
                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($SiteName)/rest/firewallrule/$($fwRule.RuleID)" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall group $GroupName successfully edited for site $SiteName"
                    
                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data #  TODO
                    }
                } else {
                    Write-Error "Firewall group $GroupName was NOT edited for site $SiteName -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No Firewall Group with ID $GroupID in site $SiteName was found"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $SiteName ($_)"
        }
        
    }
}

function Remove-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Deletes a firewall rule in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Remove-UnifiFirewallRule TODO
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

        # ID of the Firewall group to be deleted
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $RuleID,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
   
    process {
        try {
            $fwRule = Get-UnifiFirewallRule -SiteName $SiteName | Where-Object { $_.RuleID -eq $RuleID }

            if ($fwRule) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the firewall rule '$($fwRule.RuleName)' (ID: $($RuleID))? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of firewall rule '$($fwRule.RuleName)' (ID: $($RuleID)) was aborted by user"
                        return $null
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/firewallrule/$($RuleID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall rule '$($fwRule.RuleName)' successfully deleted for site $SiteName"
                } else {
                    Write-Error "Firewall rule '$($fwRule.RuleName)' was NOT deleted for site $SiteName"
                }
            } else {
                Write-Error "No Firewall rule with $RuleID was found in site $SiteName"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall rule for site $($SiteName) ($_)"
        }
        
    }
}

function Get-UnifiTag {
    <#
    .SYNOPSIS
        Gets all tags from a unifi site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Get-UnifiTag TODO
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
        $Raw
    )
   
    process {
        try {

            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/tag"

            if ($jsonResult.meta.rc -eq "ok") {
                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="TagID";E={$_._id}},
                                                        @{N="TagName";E={$_.name}},
                                                        @{N="TagMembers";E={$_.member_table}}
                }
            }

        } catch {
            Write-Warning "Something went wrong while fetching tags for site $($SiteName) ($_)"
        }
        
    }
}

function New-UnifiTag {
    <#
    .SYNOPSIS
        Creates a new firewall group in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> New-UnifiFirewallGroup TODO
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

        # Name of the tag to be created
        [Parameter(
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagName,

        # Tag members (MAC-Addresses of APs). Can also be empty
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $TagMembers = @()
    )
   
    process {
        try {

            $Body = @{
                name = $TagName
                member_table = $TagMembers
            } | ConvertTo-Json

            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/rest/tag" -Body $Body

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Tag '$TagName' successfully created for site $SiteName"

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="TagID";E={$_._id}},
                                                        @{N="TagName";E={$_.name}},
                                                        @{N="TagMembers";E={$_.member_table}}
                }
            } else {
                Write-Error "Tag '$TagName' was NOT created for site ($SiteName)"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new tag for site $($SiteName) ($_)"
        }
        
    }
}

function Edit-UnifiTag {
    <#
    .SYNOPSIS
        Edits a tag in a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Edit-UnifiTag TODO
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

        # ID of the tag to edit
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagID,

        # Name of the tag to to edit
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagName,

        # Tag members (MAC-Addresses of APs). Can also be empty
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $TagMembers = @(),

        # Mode for updating the members
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("Replace","Add","Remove")]
        [string]
        $Mode = "Add"
    )
   
    process {
        try {
            $Tag = Get-UnifiTag -SiteName $SiteName | Where-Object { $_.TagID -eq $TagID }

            if ($Tag) {

                # Use current name if no new name was given
                if ([String]::IsNullOrWhiteSpace($TagName)) {
                    $TagName = $Tag.TagName
                }

                # Use current members if no new members were given
                if ([String]::IsNullOrWhiteSpace($TagMembers)) {
                    $TagMembers = $Tag.TagMembers
                } else {
                    switch ($Mode) { # depending on the mode decide how to update the member table if $TagMembers has content
                        "Replace" {
                            $TagMembers = $TagMembers # nonsense, but it helps understand the process
                        }

                        "Add" {
                            $TagMembers += $Tag.TagMembers
                        }

                        "Remove" {
                            Write-Warning "Remove-Mode is not fully implemented yet"
                            # TODO: $TagMembers += $Tag.TagMembers | Where-Object { $_ -ne $TagMembers }
                            $TagMembers = $Tag.TagMembers
                        }
                    }
                }

                $Body = @{
                    '_id' = $Tag.TagName
                    'site_id' = $Tag.TagID
                    name = $TagName
                    member_table = $TagMembers
                } | ConvertTo-Json
                
                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/tag/$($Tag.TagID)" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Tag '$TagName' successfully edited for site $SiteName"
                    
                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                            @{N="SiteID";E={$_.site_id}},
                                                            @{N="TagID";E={$_._id}},
                                                            @{N="TagName";E={$_.name}},
                                                            @{N="TagMembers";E={$_.member_table}}
                    }
                } else {
                    Write-Error "Tag '$TagName' was NOT edited for site $SiteName -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No tag with ID $TagID in site $SiteName was found"
            }

        } catch {
            Write-Warning "Something went wrong while editing a tag for site $SiteName ($_)"
        }
        
    }
}

function Remove-UnifiTag {
    <#
    .SYNOPSIS
        Removes a tag from a site
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Remove-UnifiTag TODO
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

        # ID of the Firewall group to be deleted
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagID,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
   
    process {
        try {
            $Tag = Get-UnifiTag -SiteName $SiteName | Where-Object { $_.TagID -eq $TagID }

            if ($Tag) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the tag '$($Tag.TagName)' (ID: $($TagID))? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of tag '$($Tag.TagName)' (ID: $($TagID)) was aborted by user"
                        return $null
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/tag/$($TagID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Tag '$($Tag.TagName)' successfully deleted for site $SiteName"
                } else {
                    Write-Error "Tag '$($Tag.TagName)' was NOT deleted for site $SiteName"
                }
            } else {
                Write-Error "No Tag with ID '$TagID' was found in site $SiteName"
            }

        } catch {
            Write-Warning "Something went wrong while deleting a a tag from site $($SiteName) ($_)"
        }
        
    }
}