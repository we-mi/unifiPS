function Remove-UnifiAdmin {
    <#
    .SYNOPSIS
        Create a new unifi admin account
    .DESCRIPTION
        Create a new unifi admin account
    .NOTES
        The name and the email-address have to be unique.
    .EXAMPLE
        PS C:\> New-UnifiAdmin -Name hans -Password (Read-Host -AsSecureString -Prompt "Password")
        Will create a new user with the name "hans" and set the password for which was asked
    .OUTPUTS
        Returns 'Unifi.User'-Object when '-PassThru' is set, else nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([Unifi.User] -or $null)]

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
