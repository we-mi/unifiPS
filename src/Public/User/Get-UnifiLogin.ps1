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
