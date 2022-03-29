$Script:WebSession = $null
$Script:BaseUri = $null
$Script:RestHeaders = $null

#region internal functions
function Invoke-UnifiRestCall {
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # HTTP Method
        [Parameter(Mandatory = $True)]
        [ValidateSet("GET","POST","PUT","DELETE")]
        [string]
        $Method,

        # REST route (URI)
        [Parameter(Mandatory = $True)]
        [string]
        $Route,

        # Body for Invoke-RestMethod (will only be applied if $Method is POST, PUT or DELETE)
        [Parameter(Mandatory = $False)]
        [Object]
        $Body,

        # Custom Parameters for Invoke-RestMethod
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

        if ($script:useSkipCertParam) {
            $restParams.SkipCertificateCheck = $true
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
#endregion

#region Authentication
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
        PS C:\> Invoke-UnifiLogin -Uri https://localhost:8443/api -Timeout 5
        Logs in to the unifi server at the specified address and wait max. 5 seconds
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

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

        $TestSkipCertParam = (Get-Command Invoke-RestMethod).Parameters.SkipCertificateCheck
        if ($TestSkipCertParam) { # Parameter to skip cert is available, so why not use it
            $script:useSkipCertParam = $true
        } else { # Parameter to skip cert is not available, try a workaround
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
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            } catch {}
        }

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

        if ($script:useSkipCertParam) {
            $restParams.SkipCertificateCheck = $true
        }

        $jsonResult = Invoke-UnifiRestCall -Method POST -Route "login" -Body $Body -CustomRestParams $restParams

        $Credential = $null
        $Body = $null

        if ($jsonResult.meta.rc -eq "ok") {
            Write-Verbose "Login to Unifi-Controller successful"
            return $True
        } else {
            Write-Error "Login to Unifi-Controller failed"
            return $False
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
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param()

    process {
        $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/logout"

        if ($jsonResult.meta.rc -eq "ok") {
            Write-Verbose "Logout from Unifi-Controller successful"
            return $True
        } else {
            Write-Error "Logout from Unifi-Controller failed"
            return $False
        }
        
    }
}
#endregion

#region Unifi Controller information
function Get-UnifiServerInfo {
    <#
    .SYNOPSIS
        Grabs simple information from the unifi server (state,version,uuid)
    .DESCRIPTION
        Grabs simple information from the unifi server (state,version,uuid)
        You do not need to be logged in to grap this information
    .EXAMPLE
        PS C:\> Get-UnifiServerInfo
        Grabs the information
    .OUTPUTS
        Returns JSON-Data
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
#endregion

#region User information
function Get-UnifiLogin {
    <#
    .SYNOPSIS
        Shows information about the currently logged in user
    .DESCRIPTION
        Shows information about the currently logged in user
    .EXAMPLE
        PS C:\> Get-UnifiLogin
        Shows information about the currently logged in user
    .OUTPUTS
        Returns JSON-Data
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
    .OUTPUTS
        Returns JSON-Data
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # SiteName 
        [Parameter(Mandatory = $false, ParameterSetName="SiteName", ValueFromPipelineByPropertyName=$True)]
        [string]
        $SiteName,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw,

        # List Admins for all sites
        [Parameter(Mandatory = $false, ParameterSetName="All")]
        [switch]
        $All
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
#endregion

#region Basic site handling
function Get-UnifiSite {
    <#
    .SYNOPSIS
        Gets one or more sites of the unifi controller
    .DESCRIPTION
        Gets one or more sites of the unifi controller
        You can filter by SiteName (internal site name) or SiteID or SiteDisplayName (name visible in the web interface, unifi's internal name for this field is 'desc')
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName *
        Lists all sites
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Default","*Test*"
        Lists all sites which contains the string "Test" and the site with the name "Default"
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteName "67itznop"
        Lists the site with the SiteName '67itznop'
    .EXAMPLE
        PS C:\> Get-UnifiSite SiteID "623e1bf66a5d4f1280160b7e"
        Lists the site with the ID '623e1bf66a5d4f1280160b7e'
    .OUTPUTS
        Returns JSON-Data
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
                    $jsonResult.data | Select-Object    @{N="SiteID";E={$_._id}},
                                                        @{N="SiteDisplayName";E={$_.desc}},
                                                        @{N="SiteName";E={$_.name}},
                                                        @{N="NoDelete";E={ if ($_.attr_no_delete) {$_.attr_no_delete} else { $False }}}
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
    }
}

function New-UnifiSite {
    <#
    .SYNOPSIS
        Creates a new unifi site
    .DESCRIPTION
        Creates a new unifi site.
        It does check if a site with the same name is already present (You can have more than one site with the same DisplayName in the unifi controller (a bit stupid if you ask me...))
        If you want to disable this check, use the 'DisableNameCheck'-Switch
    .EXAMPLE
        PS C:\> New-UnifiSite -SiteDisplayName "My New Site"
        Creates the new unifi site 'My New Site'
    .EXAMPLE
        PS C:\> New-UnifiSite -SiteDisplayName "My New Site" DisableNameCheck
        Creates the new unifi site 'My New Site' even if a site with this DisplayName is already present
    .OUTPUTS
        Returns JSON-Data from the newly created site
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # (Display-)Name of the site under which it appears in the webui
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 0 )]
        [String]
        $SiteDisplayName,

        # Disable checking if a site name is already present
        [Parameter(Mandatory = $false)]
        [switch]
        $DisableNameCheck,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )
   
    process {
        try {

            if (!$DisableNameCheck) {
                $sites = Get-UnifiSite "*"

                if ($sites.SiteDisplayName -contains $SiteDisplayName) {
                    Write-Error "There's already a site with the DisplayName '$SiteDisplayName' present."
                    return ""
                }
            }

            $Body = @{
                cmd = "add-site"
                desc = $SiteDisplayName
            } | ConvertTo-Json

            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/default/cmd/sitemgr" -Body $Body

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Site '$SiteDisplayName' successfully created"

                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object    @{N="SiteName";E={$_.name}},
                                                        @{N="SiteID";E={$_._id}},
                                                        @{N="SiteDisplayName";E={$_.desc}}

                }
            } else {
               Write-Error "Site '$SiteDisplayName' was NOT created ($jsonResult.meta.msg)" 
            }

        } catch {
            Write-Warning "Something went wrong while creating a new site $($SiteDisplayName) ($_)"
        }
    }
}

function Remove-UnifiSite {
    <#
    .SYNOPSIS
        Deletes a unifi site
    .DESCRIPTION
        Deletes a unifi site. Be careful with this!
    .EXAMPLE
        PS C:\> Remove-UnifiSite -SiteName 67itznop
        Removes the unifi site with the SiteName '67itznop', but asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteDisplayName 'ProductionSite' | Remove-UnifiSite -Force
        Removes the unifi site with the DisplayName 'ProductionSite' and does NOT ask for confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([boolean])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
   
    process {
        try {
            $site = Get-UnifiSite -SiteName $SiteName

            if ($site) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the site '$($SiteName)' (DisplayName: $($site.SiteDisplayName))? Be **extremely careful with this** (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of site '$($SiteName)' (DisplayName: $($site.SiteDisplayName)) was aborted by user"
                        return $False
                    }

                }

                $Body = @{
                    site = $site.SiteID
                    cmd = "delete-site"
                } | ConvertTo-Json
                $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Site '$($SiteName)' (DisplayName: $($site.SiteDisplayName)) successfully deleted"
                    return $True
                } else {
                    Write-Error "Site '$($SiteName)' (DisplayName: $($site.SiteDisplayName)) was NOT deleted"
                    return $False
                }
            } else {
                Write-Error "No site '$SiteName' was found"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while removing site $($SiteName) ($_)"
            return $False
        }
    }
}

function Rename-UnifiSite {
    <#
    .SYNOPSIS
        Renames a unifi site
    .DESCRIPTION
        Renames a unifi site
    .EXAMPLE
        PS C:\> Rename-UnifiSite -SiteName '67itznop' -NewSiteDisplayName "my wonderful site"
        Renames the unifi site with the SiteName '67itznop' to 'my wonderful site'. Note that the SiteName keeps the same. Only the SiteDisplayName in the webui changes
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteDisplayName 'Development' | Rename-UnifiSite 
        Renames the unifi site with the SiteName '67itznop' to 'my wonderful site'. Note that the SiteName keeps the same. Only the SiteDisplayName in the webui changes
    .OUTPUTS
        Returns JSON-Data
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Name of the site which will be renamed (Unifi's internal name is used, not the name visible in the web interface) 
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # New DisplayName of the site
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [Alias("SiteDisplayName")]
        [String]
        $NewSiteDisplayName,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )
   
    process {
        try {
            $site = Get-UnifiSite -SiteName $SiteName

            if ($site) {

                if ($site.SiteDisplayName -eq $NewSiteDisplayName) {
                    Write-Warning "Nothing to do. Old and new display names match"
                } else {

                    $Body = @{
                        desc = $NewSiteDisplayName
                        cmd = "update-site"
                    } | ConvertTo-Json

                    $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body $Body

                    if ($jsonResult.meta.rc -eq "ok") {
                        Write-Verbose "Site '$($SiteName)' was renamed from '$($site.NewSiteDisplayName)' to '$NewSiteDisplayName'"
                        if ($Raw) {
                            $jsonResult.data
                        } else {
                            $jsonResult.data | Select-Object    @{N="SiteID";E={$_._id}},
                                                                @{N="NewSiteDisplayName";E={$_.desc}},
                                                                @{N="SiteName";E={$_.name}},
                                                                @{N="NoDelete";E={ if ($_.attr_no_delete) {$_.attr_no_delete} else { $False }}}
                        }

                    } else {
                        Write-Error "Site '$($SiteName)' (DisplayName: $($site.NewSiteDisplayName)) was NOT renamed"
                    }
                }
            } else {
                Write-Error "No site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while renaming site $($SiteName) ($_)"
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
#endregion

#region Log/Events/Alarms
function Get-UnifiEvent {
    <#
    .SYNOPSIS
        Gets events for a unifi site
    .DESCRIPTION
        Gets events for a unifi site. The default limit for events is 500. Use a limit of 0 to disable this limit. But note that the unifi controller api has a max limit of 3000 entries

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Test" | Get-UnifiEvent
        Gets events from site with the DisplayName "Test"
    .EXAMPLE
        PS C:\> Get-UnifiEvent -SiteName "01gg6pt0" -Limit 0
        Gets events from the site with the (internal) name "01gg6pt0". Use the unifi controllers default limit of 3000 entries
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
        Gets alarms for a unifi site. The default limit for alarms is 500. Use a limit of 0 to disable this limit. But note that the unifi controller api has a max limit of 3000 entries

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Test" | Get-UnifiAlarm
        Gets alarms from site with the DisplayName "Test"
    .EXAMPLE
        PS C:\> Get-UnifiAlarm -SiteName "01gg6pt0"
        Gets alarms from the site with the (internal) name "01gg6pt0"
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
#endregion

#region Device Management
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
    .EXAMPLE
        PS C:\> Get-UnifiSite * | Get-UnifiDevice
        Returns all devices from all sites
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
            Write-Error "Something went wrong while fetching devices ($($_.Exception))" -ErrorAction Stop
        }
    }
}

function Restart-UnifiDevice {
    <#
    .SYNOPSIS
        Restarts a unifi device
    .DESCRIPTION
        Restarts a unifi device. Use the $Force-Switch to skip asking for confirmation

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "AP01" | Restart-UnifiDevice
        Restarts the device with the name "AP01" in site "Test", but asks for confirmation
    .EXAMPLE
        PS C:\> Restart-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55" -Force
        Restarts the device with the mac "00:11:22:33:44:55" in site "Test" and does not ask for confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # MAC of the device to restart
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
                Write-Verbose "Device with MAC '$MAC' will reboot now"
                return $True
            } else {
                Write-Error "Could not reboot device mit MAC '$MAC'"
                return $False
            }

        } catch {
            Write-Error "Something went wrong while rebooting device with MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
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
        Provisions the device with the name "AP01" in site "Test"
    .EXAMPLE
        PS C:\> Sync-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55"
        Provisions the device with the mac "00:11:22:33:44:55" in site "Test"
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

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
                Write-Verbose "Device with '$MAC' will force a provision"
                return $True
            } else {
                Write-Error "Could not force a provision for device with MAC '$MAC'"
                return $False
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}

function Edit-UnifiDevice { # not tested yet
    <#
    .SYNOPSIS
        Edits a unifi device (access point, gateway, switch, etc)
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Edit-UnifiDevice TODO
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

        # ID of the Device to be edited
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceID,

        # New name of the device. Leave empty to keep the name
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceName
    )
   
    process {
        
        try {
            $Device = Get-UnifiDevice -SiteName $SiteName | Where-Object { $_.DeviceID -eq $DeviceID }

            if ($Device) {

                # Use current name if no new name was given
                if ([String]::IsNullOrWhiteSpace($DeviceName)) {
                    $DeviceName = $Device.DeviceName
                }

                $Body = @{
                    #'_id' = $Device.GroupID
                    #'site_id' = $Device.SiteID
                    name = $GroupName
                    #group_type = $Device.GroupType
                    #group_members = $GroupMembers
                } | ConvertTo-Json
                
                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/device/$($Device.DeviceID)" -Body $Body 

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Device '$DeviceName' was successfully edited for site '$SiteName'"
                    
                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data <# | Select-Object    @{N="SiteName";E={$SiteName}},
                                                            @{N="SiteID";E={$_.site_id}},
                                                            @{N="GroupID";E={$_._id}},
                                                            @{N="GroupName";E={$_.name}},
                                                            @{N="GroupMembers";E={$_.group_members}},
                                                            @{N="GroupType";E={$_.group_type}} #>
                    }
                } else {
                    Write-Error "Device '$DeviceName' was NOT edited for site '$SiteName' -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No Device with ID '$DeviceID' was found in site '$SiteName'"
            }

        } catch {
            Write-Warning "Something went wrong while editing device with ID '$DeviceID' for site $SiteName ($_)"
        }
        
    }
}
#endregion

#region Client Management
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

function Disconnect-UnifiClient {
    <#
    .SYNOPSIS
        Disconnects a unifi client device (the client will try to reconnect)
    .DESCRIPTION
        Disconnects a unifi client device (the client will try to reconnect). This function will ask for confirmation unless the $Force-Switch is used

        You can pipe the output from "Get-UnifiClient" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "iPad01" | Disconnect-UnifiClient
        Reconnects the client with the name "iPad01" in site "Test"
    .EXAMPLE
        PS C:\> Disconnect-UnifiClient -SiteName "Test" -MAC "00:11:22:33:44:55"
        Reconnects the client with the mac "00:11:22:33:44:55" in site "Test"
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([boolean])]

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
                Write-Verbose "Client '$MAC' was disconnected"
            } else {
                Write-Error "Client '$MAC' was NOT disconnected"
            }

        } catch {
            Write-Error "Something went wrong while disconnecting the client with the MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
        }
        
    }
}
#endregion

#region Firewall Management
function Get-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Lists firewall groups in a site
    .DESCRIPTION
        Lists firewall groups in a site.
        A firewall group can be a group of ports, ipv4-addresses or ipv6-addresses. This group is then used in a firewall rule
    .EXAMPLE
        PS C:\> Get-UnifiFirewallGroup -SiteName "default"
        Lists the firewall groups for the default site
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
            Write-Warning "Something went wrong while fetching firewall groups for site $($SiteName) ($_)"
        }        
    }
}

function New-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Creates a new firewall group in a site
    .DESCRIPTION
        Creates a new firewall group in a site

        Ports can be separated by a comma (20,21,22) and/or specified as a range (5900-5910)
        IP-Address can also be separated by a comma and/or specified as a network address (10.0.0.0/8)
    .EXAMPLE
        PS C:\> New-UnifiFirewallGroup -SiteName "default" -GroupName "FTP-Ports" -GroupMembers 20,21 -GroupType port-group
        Creates the firewall group "FTP-Ports" in the default site as a "port-group" and assigns the ports 20&21 to it
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteName "Production" | New-UnifiFirewallGroup -GroupName "Internal Networks" -GroupType "address-group" -GroupMembers "192.168.0.0/24","192.168.100.0/24"
        Creates the firewall group "Internal Networks" in the "Production" site as an "address-group" and assigns the networks 192.168.0.0/24 and 192.168.100.0/24 to it
    .OUTPUTS
        Returns JSON-Data for the newly created object
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
                Write-Verbose "Firewall group '$GroupName' successfully created for site '$SiteName'"

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
                    Write-Warning "Firewall group '$GroupName' already exists in site '$SiteName'"
                } else {
                    Write-Error "Firewall group '$GroupName' was NOT created for site '$SiteName'"
                }
            }

        } catch {
            Write-Warning "Something went wrong while creating a new firewall group for site $($SiteName) ($_)"
        }
    }
}

function Edit-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Edits a firewall group for a site
    .DESCRIPTION
        Edits a firewall group for a site

        You can only change the name and the members of the firewall group, but you cannot change the group-type

        Leave the name or the members empty to keep them
    .EXAMPLE
        PS C:\> Get-UnifiSite "default" | Get-UnifiFirewallGroup -GroupName "FTP-Ports" | Edit-UnifiFirewallGroup -GroupName "RDP-Ports" -GroupMembers 3389
        Changes the name and the ports of the firewall group "FTP-Ports" in the default site
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

        # Group members (can be ipv4/ipv6 addresses or port numbers/ranges). Can also be empty. All members will be overridden by this parameter
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

                if ( $GroupName -eq $fwGroup.GroupName -and $GroupMembers -eq $fwGroup.GroupMembers) {
                    Write-Warning "Nothing has changed"
                } else {
                    # Use current name if no new name was given
                    if ([String]::IsNullOrWhiteSpace($GroupName)) {
                        $GroupName = $fwGroup.GroupName
                    }

                    # Use current members if no new members were given
                    if ([String]::IsNullOrWhiteSpace($GroupMembers)) {
                        $GroupMembers = $fwGroup.GroupMembers
                    }

                    $Body = @{
                        '_id' = $fwGroup.GroupID
                        'site_id' = $fwGroup.SiteID
                        name = $GroupName
                        group_type = $fwGroup.GroupType
                        group_members = @($GroupMembers)
                    } | ConvertTo-Json
                    
                    $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/firewallgroup/$($fwGroup.GroupID)" -Body $Body

                    if ($jsonResult.meta.rc -eq "ok") {
                        Write-Verbose "Firewall group '$GroupName' successfully edited for site '$SiteName'"
                        
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
                        Write-Error "Firewall group '$GroupName' was NOT edited for site '$SiteName' -> error: $($jsonResult.meta.msg)"
                    }
                }
            } else {
                Write-Error "No Firewall Group with ID '$GroupID' in site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while editing firewall group with ID '$GroupID' for site $SiteName ($_)"
        }        
    }
}

function Remove-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Deletes a firewall group in a site
    .DESCRIPTION
        Deletes a firewall group in a site and asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiSite "default" | Get-UnifiFirewallGroup -GroupName "FTP-Ports" | Remove-UnifiFirewallGroup -Force
        Removes the firewall group "FTP-Ports" in the "default" site and skips confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

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
                        return $False
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/firewallgroup/$($GroupID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall group '$($fwGroup.GroupName)' successfully deleted for site $SiteName"
                    return $True
                } else {
                    Write-Error "Firewall group '$($fwGroup.GroupName)' was NOT deleted for site $SiteName"
                    return $False
                }
            } else {
                Write-Error "No Firewall Group with '$GroupID' was found in site '$SiteName'"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while deleting the firewall group with ID '$GroupID' for site $($SiteName) ($_)"
            return $False
        }        
    }
}

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

function Remove-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Deletes a firewall rule in a site
    .DESCRIPTION
        Deletes a firewall rule in a site and asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiSite "test" | Get-UnifiFirewallRule -RuleName "Allow RDP" | Remove-UnifiFirewallRule -Force
        Removes the firewall rule "Allow RDP" from the site "test" and does not ask for confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

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
                        return $False
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/firewallrule/$($RuleID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall rule '$($fwRule.RuleName)' successfully deleted for site $SiteName"
                    return $True
                } else {
                    Write-Error "Firewall rule '$($fwRule.RuleName)' was NOT deleted for site $SiteName"
                    return $False
                }
            } else {
                Write-Error "No Firewall rule with ID '$RuleID' was found in site '$SiteName'"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while removing firewall rule with ID '$($RuleID)' for site '$($SiteName)' ($_)"
        }
    }
}
#endregion

#region Tag Management
function Get-UnifiTag {
    <#
    .SYNOPSIS
        Gets all tags from a unifi site
    .DESCRIPTION
        Gets all tags from a unifi site
    .EXAMPLE
        PS C:\> Get-UnifiTag -SiteName "default"
        Get all tags from the "default" site
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
            Write-Warning "Something went wrong while fetching tags for site '$($SiteName)' ($_)"
        }
    }
}

function New-UnifiTag {
    <#
    .SYNOPSIS
        Creates a new tag for a site
    .DESCRIPTION
        Creates a new tag for a site
    .EXAMPLE
        PS C:\> New-UnifiTag -SiteName "default" -TagName "Building-A" -TagMembers "00:11:22:33:44:55","66:77:88:99:AA:BB:CC"
        Creates the new Tag "Building-A" in the "default" site and assigns the Devices with the macs "00:11:22:33:44:55","66:77:88:99:AA:BB:CC" to it
    .OUTPUTS
        Returns JSON data
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
                Write-Verbose "Tag '$TagName' successfully created for site '$SiteName'"

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
                Write-Error "Tag '$TagName' was NOT created for site '$SiteName')'"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new tag for site '$($SiteName)' ($_)"
        }        
    }
}

function Edit-UnifiTag {
    <#
    .SYNOPSIS
        Edits a tag in a site
    .DESCRIPTION
        Edits a tag in a site
        You can control what should happen with $TagMembers by specifying the $Mode-Parameter
        $Mode = "Add" -> Add given Members to current TagMembers. This is the default
        $Mode = "Replace" -> Replace given members with current TagMembers
        $Mode = "Remove" -> Remove given members from current TagMembers (TODO: not implemented yet)
    .EXAMPLE
        PS C:\> Get-UnifiTag -SiteName "default" | Where-Object { $_.TagName -eq "Building-A" } | Edit-UnifiTag -GroupMembers "00:11:22:33:44:55","66:77:88:99:AA:BB:CC" -Mode Replace
        Edits the tag "Building-A" in the "default" site and replaces the members with "00:11:22:33:44:55","66:77:88:99:AA:BB:CC"
    .OUTPUTS
        Returns JSON-data
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
                            $TagMembers = $TagMembers # nonsense, but it helps to understand the process
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
                Write-Error "No tag with ID '$TagID' in site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while editing a tag for site '$SiteName' ($_)"
        }
        
    }
}

function Remove-UnifiTag {
    <#
    .SYNOPSIS
        Removes a tag from a site
    .DESCRIPTION
        Removes a tag from a site and asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiTag -SiteName "default" | Where-Object { $_.TagName -eq "Building-A" } | Remove-UnifiTag -Force
        Removes the tag "Building-A" from the "default" site and skips confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

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
                        return $False
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/tag/$($TagID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Tag '$($Tag.TagName)' successfully deleted for site $SiteName"
                    return $True
                } else {
                    Write-Error "Tag '$($Tag.TagName)' was NOT deleted for site $SiteName"
                    return $False
                }
            } else {
                Write-Error "No Tag with ID '$TagID' was found in site $SiteName"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while deleting a a tag from site $($SiteName) ($_)"
            return $False
        }
    }
}
#endregion