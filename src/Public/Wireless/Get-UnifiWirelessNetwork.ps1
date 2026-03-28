function Get-UnifiWirelessNetwork {
    <#
    .SYNOPSIS
        Gets wireless networks of a unifi site
    .DESCRIPTION
        Gets wireless networks of a unifi site

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiDevice -SiteName "default" | Get-UnifiWirelessNetwork
        Returns all wireless networks from site "default"
    .EXAMPLE
        PS C:\> Get-UnifiSite * | Get-UnifiWirelessNetwork
        Returns all wireless networks from all sites
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

        # Show the PSK as plaintext
        [Parameter(Mandatory = $false)]
        [switch]
        $ShowPassphrase,

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/rest/wlanconf"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Raw) {
                    $jsonResult.data
                } else {
                    Build-UnifiWirelessNetworkObject $jsonResult.data
                }
            }

        } catch {
            Write-Error "Something went wrong while fetching wireless networks for site '$SiteName' ($($_.Exception))" -ErrorAction Stop
        }
    }
}
