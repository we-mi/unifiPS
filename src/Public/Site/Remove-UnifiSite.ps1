function Remove-UnifiSite {
    <#
    .SYNOPSIS
        Deletes a unifi site
    .DESCRIPTION
        Deletes a unifi site. Be careful with this!
    .EXAMPLE
        PS C:\> Remove-UnifiSite -SiteName 67itznop
        Removes the unifi site with the SiteName '67itznop', but asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiSite -SiteDisplayName 'ProductionSite' | Remove-UnifiSite -Force
        Removes the unifi site with the DisplayName 'ProductionSite' and does NOT ask for confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([boolean])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    process {
        try {
            $site = Get-UnifiSite -SiteName $SiteName

            if ($site) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the site '$($SiteName)' (DisplayName: $($site.SiteDisplayName))? Be **extremely careful with this** (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of site '$($SiteName)' (DisplayName: $($site.SiteDisplayName)) was aborted by user"
                        return $False
                    }

                }

                $Body = @{
                    site = $site.SiteID
                    cmd = "delete-site"
                } | ConvertTo-Json
                $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/sitemgr" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Site '$($SiteName)' (DisplayName: $($site.SiteDisplayName)) successfully deleted"
                    return $True
                } else {
                    Write-Error "Site '$($SiteName)' (DisplayName: $($site.SiteDisplayName)) was NOT deleted"
                    return $False
                }
            } else {
                Write-Error "No site '$SiteName' was found"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while removing site $($SiteName) ($_)"
            return $False
        }
    }
}
