function Remove-UnifiFirewallGroup {
    <#
    .SYNOPSIS
        Deletes a firewall group in a site
    .DESCRIPTION
        Deletes a firewall group in a site and asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiSite "default" | Get-UnifiFirewallGroup -GroupName "FTP-Ports" | Remove-UnifiFirewallGroup -Force
        Removes the firewall group "FTP-Ports" in the "default" site and skips confirmation
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

        # ID of the Firewall group to be deleted
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $GroupID,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    process {
        try {
            $fwGroup = Get-UnifiFirewallGroup -SiteName $SiteName | Where-Object { $_.GroupID -eq $GroupID }

            if ($fwGroup) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the firewall group '$($fwGroup.GroupName)' (ID: $($GroupID))? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of firewall group '$($fwGroup.GroupName)' (ID: $($GroupID)) was aborted by user"
                        return $False
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/firewallgroup/$($GroupID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall group '$($fwGroup.GroupName)' successfully deleted for site $SiteName"
                    return $True
                } else {
                    Write-Error "Firewall group '$($fwGroup.GroupName)' was NOT deleted for site $SiteName"
                    return $False
                }
            } else {
                Write-Error "No Firewall Group with '$GroupID' was found in site '$SiteName'"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while deleting the firewall group with ID '$GroupID' for site $($SiteName) ($_)"
            return $False
        }
    }
}
