function Edit-UnifiTag {
    <#
    .SYNOPSIS
        Edits a tag in a site
    .DESCRIPTION
        Edits a tag in a site
        You can control what should happen with $TagMembers by specifying the $Mode-Parameter
        $Mode = "Add" -> Add given Members to current TagMembers. This is the default
        $Mode = "Replace" -> Replace given members with current TagMembers
        $Mode = "Remove" -> Remove given members from current TagMembers (TODO: not implemented yet)
    .EXAMPLE
        PS C:\> Get-UnifiTag -SiteName "default" | Where-Object { $_.TagName -eq "Building-A" } | Edit-UnifiTag -GroupMembers "00:11:22:33:44:55","66:77:88:99:AA:BB:CC" -Mode Replace
        Edits the tag "Building-A" in the "default" site and replaces the members with "00:11:22:33:44:55","66:77:88:99:AA:BB:CC"
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

        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw,

        # ID of the tag to edit
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagID,

        # Name of the tag to to edit
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagName,

        # Tag members (MAC-Addresses of APs). Can also be empty
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $TagMembers = @(),

        # Mode for updating the members
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("Replace","Add","Remove")]
        [string]
        $Mode = "Add"
    )

    process {
        try {
            $Tag = Get-UnifiTag -SiteName $SiteName | Where-Object { $_.TagID -eq $TagID }

            if ($Tag) {

                # Use current name if no new name was given
                if ([String]::IsNullOrWhiteSpace($TagName)) {
                    $TagName = $Tag.TagName
                }

                # Use current members if no new members were given
                if ([String]::IsNullOrWhiteSpace($TagMembers)) {
                    $TagMembers = $Tag.TagMembers
                } else {
                    switch ($Mode) { # depending on the mode decide how to update the member table if $TagMembers has content
                        "Replace" {
                            $TagMembers = $TagMembers # nonsense, but it helps to understand the process
                        }

                        "Add" {
                            $TagMembers += $Tag.TagMembers
                        }

                        "Remove" {
                            Write-Warning "Remove-Mode is not fully implemented yet"
                            # TODO: $TagMembers += $Tag.TagMembers | Where-Object { $_ -ne $TagMembers }
                            $TagMembers = $Tag.TagMembers
                        }
                    }
                }

                $Body = @{
                    '_id' = $Tag.TagName
                    'site_id' = $Tag.TagID
                    name = $TagName
                    member_table = $TagMembers
                } | ConvertTo-Json

                $jsonResult = Invoke-UnifiRestCall -Method PUT -Route "api/s/$($siteName)/rest/tag/$($Tag.TagID)" -Body $Body

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Tag '$TagName' successfully edited for site $SiteName"

                    if ($Raw) {
                        $jsonResult.data
                    } else {
                        $jsonResult.data | Select-Object    @{N="SiteName";E={$SiteName}},
                                                            @{N="SiteID";E={$_.site_id}},
                                                            @{N="TagID";E={$_._id}},
                                                            @{N="TagName";E={$_.name}},
                                                            @{N="TagMembers";E={$_.member_table}}
                    }
                } else {
                    Write-Error "Tag '$TagName' was NOT edited for site $SiteName -> error: $($jsonResult.meta.msg)"
                }
            } else {
                Write-Error "No tag with ID '$TagID' in site '$SiteName' was found"
            }

        } catch {
            Write-Warning "Something went wrong while editing a tag for site '$SiteName' ($_)"
        }

    }
}
