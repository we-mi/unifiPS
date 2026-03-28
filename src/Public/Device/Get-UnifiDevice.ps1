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
                    Build-UnifiClientObject $jsonResult.data
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching devices ($($_.Exception))" -ErrorAction Stop
        }
    }
}
