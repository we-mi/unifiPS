function Disconnect-UnifiClient {
    <#
    .SYNOPSIS
        Disconnects a unifi client device (the client will try to reconnect)
    .DESCRIPTION
        Disconnects a unifi client device (the client will try to reconnect). This function will ask for confirmation unless the $Force-Switch is used

        You can pipe the output from "Get-UnifiClient" to this cmdlet
    .EXAMPLE
        PS C:\> Get-UnifiSite "Test" | Get-UnifiDevice "iPad01" | Disconnect-UnifiClient
        Reconnects the client with the name "iPad01" in site "Test"
    .EXAMPLE
        PS C:\> Disconnect-UnifiClient -SiteName "Test" -MAC "00:11:22:33:44:55"
        Reconnects the client with the mac "00:11:22:33:44:55" in site "Test"
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

        # MAC of the client to reconnect
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $MAC,

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
            if (!$Force) {
                do {
                    $answer = Read-Host -Prompt "Do you really want to disconnect the client '$MAC'? (y/N): "
                } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                if ($answer -eq "" -or $answer -eq "n") {
                    Write-Verbose "Disconnecting the client '$MAC' was aborted by user"
                    return $null
                }

            }
            $jsonResult = Invoke-UnifiRestCall -Method POST -Route "api/s/$($SiteName)/cmd/stamgr" -Body (@{cmd = "kick-sta"; mac = $MAC} | ConvertTo-JSON)

            if ($jsonResult.meta.rc -eq "ok") {
                Write-Verbose "Client '$MAC' was disconnected"
            } else {
                Write-Error "Client '$MAC' was NOT disconnected"
            }

        } catch {
            Write-Error "Something went wrong while disconnecting the client with the MAC '$MAC' ($($_.Exception))" -ErrorAction Stop
        }

    }
}
