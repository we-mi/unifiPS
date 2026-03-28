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
