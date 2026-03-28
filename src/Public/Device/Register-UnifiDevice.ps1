function Register-UnifiDevice {
    <#
    .SYNOPSIS
        Registers (adopts) a unifi device to the unifi controller
    .DESCRIPTION
        Registers (adopts) a unifi device to the unifi controller

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice | Where-Object { $_.State -eq "Pending Adoption" } | Register-UnifiDevice
        Adopts all devices which can be adopted in site "Test"
    .EXAMPLE
        PS C:\> Register-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55"
        Adopts the device with the mac "00:11:22:33:44:55" in site "Test"
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

        # MAC of the device to register (adopt)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC
    )

    process {

        try {
            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/devmgr" -Body (@{cmd = "adopt"; mac = $MAC} | ConvertTo-JSON)

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Device with '$MAC' was adopted."
                return $True
            } else {
                Write-Error "Could not adopt device with MAC '$MAC'"
                return $False
            }

        } catch {
            Write-Error "Something went wrong while adopting device with MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
        }

    }
}
