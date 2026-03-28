function Edit-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Edits a firewall group for a site
    .DESCRIPTION
        Edits a firewall group for a site

        You can only change the name and the members of the firewall group, but you cannot change the group-type

        Leave the name or the members empty to keep them
    .EXAMPLE
        PS C:\> Get-UnifiSite "default" | Get-UnifiFirewallGroup -GroupName "FTP-Ports" | Edit-UnifiFirewallGroup -GroupName "RDP-Ports" -GroupMembers 3389
        Changes the name and the ports of the firewall group "FTP-Ports" in the default site
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
        $Raw,

        # ID of the Firewall group to be edited
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupID,

        # New name of the group. Leave empty to keep the name
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupName,

        # Group members (can be ipv4/ipv6 addresses or port numbers/ranges). Can also be empty. All members will be overridden by this parameter
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $GroupMembers = @()
    )

    process {

        try {
            $fwGroup = Get-UnifiFirewallGroup -SiteName $SiteName | Where-Object { $_.GroupID -eq $GroupID }

            if ($fwGroup) {

                if ( $GroupName -eq $fwGroup.GroupName -and $GroupMembers -eq $fwGroup.GroupMembers) {
                    Write-Warning "Nothing has changed"
                } else {
                    # Use current name if no new name was given
                    if ([String]::IsNullOrWhiteSpace($GroupName)) {
                        $GroupName = $fwGroup.GroupName
                    }

                    # Use current members if no new members were given
                    if ([String]::IsNullOrWhiteSpace($GroupMembers)) {
                        $GroupMembers = $fwGroup.GroupMembers
                    }

                    $Body = @{
                        '_id' = $fwGroup.GroupID
                        'site_id' = $fwGroup.SiteID
                        name = $GroupName
                        group_type = $fwGroup.GroupType
                        group_members = @($GroupMembers)
                    } | ConvertTo-Json

                    $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/firewallgroup/$($fwGroup.GroupID)" -Body $Body

                    if ($jsonResult.meta.rc -eq "ok") {
                        Write-Verbose "Firewall group '$GroupName' successfully edited for site '$SiteName'"

                        if ($Raw) {
                            $jsonResult.data
                        } else {
                            $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                                @{N="SiteID";E={$_.site_id}},
                                                                @{N="GroupID";E={$_._id}},
                                                                @{N="GroupName";E={$_.name}},
                                                                @{N="GroupMembers";E={$_.group_members}},
                                                                @{N="GroupType";E={$_.group_type}}
                        }
                    } else {
                        Write-Error "Firewall group '$GroupName' was NOT edited for site '$SiteName' -> error: $($jsonResult.meta.msg)"
                    }
                }
            } else {
                Write-Error "No Firewall Group with ID '$GroupID' in site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while editing firewall group with ID '$GroupID' for site $SiteName ($_)"
        }
    }
}
