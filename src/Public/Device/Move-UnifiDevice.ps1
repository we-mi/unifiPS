function Move-UnifiDevice {
    <#
    .SYNOPSIS
        Moves a unifi device to another site
    .DESCRIPTION
        Moves a unifi device to another site

        You can pipe the output from "Get-UnifiDevice" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice | Where-Object { $_.Name -eq "AP01" } | Move-UnifiDevice -NewSiteName "oyrjfomm"
        Moves the device with the name "AP01" from site "Test" to the site with the internal name "oyrjfomm"
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

        # MAC of the device to sync
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC,

        # Name of the new site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $NewSiteName,

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
            $newSite = Get-UnifiSite -SiteName $NewSiteName
            if ($newSite) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to move the device '$MAC' from site '$SiteName' to site '$($newSite.SiteDisplayName)'? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Moving device '$MAC' was aborted by user"
                        return ""
                    }
                }
                $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body (@{cmd = "move-device"; mac = $MAC; site = $newSite.SiteID } | ConvertTo-JSON)

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Device with '$MAC' was moved to site '$($newSite.SiteDisplayName)'."
                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        Build-UnifiClientObject $jsonResult.data
                    }
                } else {
                    Write-Error "Could not move device with MAC '$MAC'"
                    return $jsonResult
                }
            } else {
                Write-Error "There is no new site with the name '$($newSite.SiteDisplayName)'"
                return ""
            }

        } catch {
            Write-Error "Something went wrong while moving device with MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
            return ""
        }

    }
}
