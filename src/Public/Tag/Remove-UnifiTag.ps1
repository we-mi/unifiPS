function Remove-UnifiTag {
    <#
    .SYNOPSIS
        Removes a tag from a site
    .DESCRIPTION
        Removes a tag from a site and asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiTag -SiteName "default" | Where-Object { $_.TagName -eq "Building-A" } | Remove-UnifiTag -Force
        Removes the tag "Building-A" from the "default" site and skips confirmation
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
        $TagID,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    process {
        try {
            $Tag = Get-UnifiTag -SiteName $SiteName | Where-Object { $_.TagID -eq $TagID }

            if ($Tag) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the tag '$($Tag.TagName)' (ID: $($TagID))? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of tag '$($Tag.TagName)' (ID: $($TagID)) was aborted by user"
                        return $False
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/tag/$($TagID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Tag '$($Tag.TagName)' successfully deleted for site $SiteName"
                    return $True
                } else {
                    Write-Error "Tag '$($Tag.TagName)' was NOT deleted for site $SiteName"
                    return $False
                }
            } else {
                Write-Error "No Tag with ID '$TagID' was found in site $SiteName"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while deleting a a tag from site $($SiteName) ($_)"
            return $False
        }
    }
}
