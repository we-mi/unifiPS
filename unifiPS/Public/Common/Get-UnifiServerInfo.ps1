function Get-UnifiServerInfo {
    <#
    .SYNOPSIS
        Grabs simple information from the unifi server (state,version,uuid)
    .DESCRIPTION
        Grabs simple information from the unifi server (state,version,uuid)
        You do not need to be logged in to grap this information
    .EXAMPLE
        PS C:\> Get-UnifiServerInfo
        Grabs the information
    .OUTPUTS
        Returns JSON-Data
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # Do not filter or rename output, just sent the json result back as raw data
        [Parameter(Mandatory = $false)]
        [switch]
        $Raw
    )

    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "status"

        if ($jsonResult.meta.rc -eq "ok") {
            if ($Raw) {
                $jsonResult.meta
            } else {
                $jsonResult.meta | Select-Object UUID,@{N="Version";E={$_.server_version}},@{N="URI";E={$Script:BaseUri}}
            }
        }
    }
}
