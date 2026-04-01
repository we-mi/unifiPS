function Remove-UnifiAdmin {
    <#
    .SYNOPSIS
        Remove a unifi admin account
    .DESCRIPTION
        Remove a unifi admin account
    .NOTES
        You can only remove admins in the default site right now. More will come soon
    .EXAMPLE
        PS C:\> Remove-UnifiAdmin -Name hans
        Will remove the user with the name "hans"
    .EXAMPLE
        PS C:\> Get-UnifiAdmin | Remove-UnifiAdmin
        Will remove every user but yourself. You propably don't want to do this
    .OUTPUTS
        Nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]

    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="String")]
        [String]$UserName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="Object")]
        [Unifi.User]$UserObject
    )

    begin {
        # Get a list of all users or just us before we do anything
        $allUsers = Get-UnifiAdmin
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq "String") {
            # we only got a username. Get the Unifi-Object of it
            $UserObject = $allUsers | Where-Object { $_.Name -eq $UserName }
        }

        $Body = @{
            admin = $allUsers | Where-Object { $_.Name -eq $UserObject.Name } | Select-Object -ExpandProperty ID -First 1
            cmd = "revoke-admin"
        }


        $Method = "POST"
        $Route = "s/default/cmd/sitemgr" # removing a user requires a site. We use the default site here, because it's already there without reading all sites first

        if ( $PSCmdlet.ShouldProcess($UserObject.Name, "Remove unifi admin") ) {
            $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
        }
    }
}
