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
