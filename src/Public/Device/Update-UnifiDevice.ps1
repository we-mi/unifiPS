function Update-UnifiDevice {
    <#
    .SYNOPSIS
        Installs/updates the firmware of a unifi device
    .DESCRIPTION
        Installs/updates the firmware of a unifi device.

        If you omit the $URL-Parameter the device will receive the latest firmware from the unifi controller.

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "AP01" | Update-UnifiDevice
        Updates the device with the name "AP01" in site "Test"
    .EXAMPLE
        PS C:\> Update-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55" -URL "https://dl.ui.com/unifi/firmware/U7HD/5.43.56.12784/BZ.ipq806x_5.43.56+12784.211209.2339.bin"
        Installs the firmware found in $URL to the device with the mac "00:11:22:33:44:55" in site "Test"
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

        # MAC of the device to update
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC,

        # URL of the custom update
        [Parameter(Mandatory = $false )]
        [String]
        $URL,

        # Wait for the update to complete before returning
        [Parameter(Mandatory = $false )]
        [Switch]
        $Wait,

        # Time in seconds to wait for the update to finish. Default is 300 seconds (5 minutes)
        [Parameter(Mandatory = $false )]
        [int]
        $WaitTimeout = 300,

        # Forcing the update (do not check device state before initiating the update and do not ask for confirmation)
        [Parameter(Mandatory = $false )]
        [Switch]
        $Force
    )

    process {

        try {

            $device = Get-UnifiDevice -SiteName $SiteName | Where-Object { $_.MAC -eq $MAC }
            if ($device) {
                if ($device.UpdateAvailable -eq $True -or $URL) {
                    if ($device.state -eq "Connected") {
                        if (!$Force) {
                            do {
                                if ($URL) {
                                    $answer = Read-Host -Prompt "Do you really want to update the device '$($device.Name)' with the firmware from URL '$URL'? (y/N): "
                                } else {
                                    $answer = Read-Host -Prompt "Do you really want to update the device '$($device.Name)'' to firmware '$($device.UpdateableFirmware)'? (y/N): "
                                }
                            } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                            if ($answer -eq "" -or $answer -eq "n") {
                                Write-Verbose "Update of device '$($device.Name)' was aborted by user"
                                return $False
                            }

                        }
                        if ($URL) {
                            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/devmgr" -Body (@{cmd = "upgrade-external"; mac = $MAC; url = $URL} | ConvertTo-JSON)
                        } else {
                            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/devmgr" -Body (@{cmd = "upgrade"; mac = $MAC } | ConvertTo-JSON)
                        }

                        if ($jsonResult.meta.rc -eq "ok") {
                            Write-Verbose "Device '$($device.Name)' is updating"

                            $now = Get-Date
                            if ($Wait) {
                                do {
                                    $device = Get-UnifiDevice -SiteName $SiteName | Where-Object { $_.MAC -eq $MAC }
                                    Write-Verbose "Device '$($Device.Name)' is still updating. Checking again in 30 seconds"
                                    Start-Sleep -Seconds 30
                                    if ( ((Get-Date) - $now).TotalSeconds -gt $WaitTimeout ) {
                                        Write-Warning "Wait-Timeout ($WaitTimeout seconds) reached. Do not wait any longer for the update to finish..."
                                        break
                                    }
                                } while ($device.State -like "Updating*")
                            }
                            return $True
                        } else {
                            Write-Error "Device '$($device.Name)' could not do a firmware update from URL '$URL'"
                            return $False
                        }
                    } else {
                        Write-Error "Device '$($device.Name)' is not in 'connected'-state"
                        return $False
                    }
                } else {
                    Write-Error "Device '$($device.Name)' already has the latest firmware installed"
                    return $False
                }
            } else {
                Write-Error "Device with MAC '$MAC' was not found in site '$SiteName'"
                return $False
            }

        } catch {
            Write-Error "Something went wrong while doing a firmware update for Device with MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
            return $False
        }
    }
}
