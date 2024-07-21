function New-UnifiTag {
    <#
    .SYNOPSIS
        Creates a new tag for a site
    .DESCRIPTION
        Creates a new tag for a site
    .EXAMPLE
        PS C:\> New-UnifiTag -SiteName "default" -TagName "Building-A" -TagMembers "00:11:22:33:44:55","66:77:88:99:AA:BB:CC"
        Creates the new Tag "Building-A" in the "default" site and assigns the Devices with the macs "00:11:22:33:44:55","66:77:88:99:AA:BB:CC" to it
    .OUTPUTS
        Returns JSON data
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

        # Name of the tag to be created
        [Parameter(
            Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $TagName,

        # Tag members (MAC-Addresses of APs). Can also be empty
        [Parameter(
            Mandatory = $false
        )]
        [string[]]
        $TagMembers = @()
    )

    process {
        try {

            $Body = @{
                name = $TagName
                member_table = $TagMembers
            } | ConvertTo-Json

            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/rest/tag" -Body $Body

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Tag '$TagName' successfully created for site '$SiteName'"

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
                Write-Error "Tag '$TagName' was NOT created for site '$SiteName')'"
            }

        } catch {
            Write-Warning "Something went wrong while creating a new tag for site '$($SiteName)' ($_)"
        }
    }
}
