function Get-UnifiEvent {
    <#
    .SYNOPSIS
        Gets events for a unifi site
    .DESCRIPTION
        Gets events for a unifi site. The default limit for events is 500. Use a limit of 0 to disable this limit. But note that the unifi controller api has a max limit of 3000 entries

        You can pipe the output from "Get-UnifiSite" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite -DisplayName "Test" | Get-UnifiEvent
        Gets events from site with the DisplayName "Test"
    .EXAMPLE
        PS C:\> Get-UnifiEvent -SiteName "01gg6pt0" -Limit 0
        Gets events from the site with the (internal) name "01gg6pt0". Use the unifi controllers default limit of 3000 entries
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

        # Limit the number of results as the output can be too big and slow. Zero means no limit
        [Parameter(Mandatory = $false)]
        [int16]
        $Limit = 500
    )

    process {

        try {
            $jsonResult = Invoke-UnifiRestCall -Method GET -Route "api/s/$($SiteName)/stat/event"

            if ($jsonResult.meta.rc -eq "ok") {

                if ($Limit -gt 0) {
                    $jsonResult.data = $jsonResult.data | Select-Object -First $Limit
                }
                if ($Raw) {
                    $jsonResult.data
                } else {
                    $jsonResult.data | Select-Object -ExcludeProperty "site_id","key","msg","_id","time","is_negative" @{N="SiteName";E={$SiteName}},
                                                        @{N="SiteID";E={$_.site_id}},
                                                        @{N="Category";E={$_.subsystem}},
                                                        @{N="Date";E={$_.DateTime}},
                                                        @{N="EventType";E={$_.key}},
                                                        @{N="Message";E={$_.msg}},
                                                        *

                }
            }

        } catch {
            Write-Error "Something went wrong while fetching sites ($($_.Exception))" -ErrorAction Stop
        }

    }
}
