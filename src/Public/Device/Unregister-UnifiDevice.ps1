function Unregister-UnifiDevice {
    <#
    .SYNOPSIS
        Unregisters (forgets) a unifi device from the unifi controller
    .DESCRIPTION
        Unregisters (forgets) a unifi device from the unifi controller

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice | Where-Object { $_.State -eq "Disconnected" } | Unregister-UnifiDevice
        Forgets all devices which are disconnected in site "Test"
    .EXAMPLE
        PS C:\> Unregister-UnifiDevice -SiteName "Test" -MAC "00:11:22:33:44:55" -Force
        Forgets the device with the mac "00:11:22:33:44:55" in site "Test" and does not ask for confirmation
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

        # MAC of the device to unregister (forget)
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
                    $answer = Read-Host -Prompt "Do you really want to forget(delete) the device '$MAC' from site '$SiteName'? (y/N): "
                } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                if ($answer -eq "" -or $answer -eq "n") {
                    Write-Verbose "Forgetting device '$MAC' was aborted by user"
                    return ""
                }
            }
            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body (@{cmd = "delete-device"; mac = $MAC} | ConvertTo-JSON)

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Device with '$MAC' was forgotten."
                if ($Raw) {
                    $jsonResult.data
                } else {
                    Build-UnifiClientObject $jsonResult.data
                }
            } else {
                Write-Error "Could not forget device with MAC '$MAC'"
                return $jsonResult
            }

        } catch {
            Write-Error "Something went wrong while forgetting device with MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
            return ""
        }

    }
}
