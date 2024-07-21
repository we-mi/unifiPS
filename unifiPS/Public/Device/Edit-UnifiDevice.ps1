function Edit-UnifiDevice { # not tested yet
    <#
    .SYNOPSIS
        Edits a unifi device (access point, gateway, switch, etc)
    .DESCRIPTION
        TODO
    .EXAMPLE
        PS C:\> Edit-UnifiDevice TODO
    .EXAMPLE
        PS C:\> TODO
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
        $Raw,

        # ID of the Device to be edited
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceID,

        # New name of the device. Leave empty to keep the name
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $DeviceName
    )

    process {

        try {
            $Device = Get-UnifiDevice -SiteName $SiteName | Where-Object { $_.DeviceID -eq $DeviceID }

            if ($Device) {

                # Use current name if no new name was given
                if ([String]::IsNullOrWhiteSpace($DeviceName)) {
                    $DeviceName = $Device.DeviceName
                }

                $Body = @{
                    #'_id' = $Device.GroupID
                    #'site_id' = $Device.SiteID
                    name = $GroupName
                    #group_type = $Device.GroupType
                    #group_members = $GroupMembers
                } | ConvertTo-Json

                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/device/$($Device.DeviceID)" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Device '$DeviceName' was successfully edited for site '$SiteName'"

                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        Build-UnifiClientObject $jsonResult.data
                    }
                } else {
                    Write-Error "Device '$DeviceName' was NOT edited for site '$SiteName' -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No Device with ID '$DeviceID' was found in site '$SiteName'"
            }

        } catch {
            Write-Warning "Something went wrong while editing device with ID '$DeviceID' for site $SiteName ($_)"
        }

    }
}
