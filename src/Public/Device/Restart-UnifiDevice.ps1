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
