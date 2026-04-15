function New-UnifiAdmin {
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
        [Parameter(Mandatory)]
        [String]$Name,

        [Parameter()]
        [String]$Email,

        [Parameter()]
        [SecureString]$Password,

        [Parameter()]
        [switch]$DoNotRequireNewPassword,

        [Parameter()]
        [switch]$PassThru
    )

    process {

        $Body = @{
            cmd = "create-admin"
            name = $Name
        }

        if ( ![String]::IsNullOrWhiteSpace($Email) ) {
            $Body.email = $Email
        }

        if ( $null -ne $Password ) {
            $Body.x_password = [System.Management.Automation.PSCredential]::new("dummy",$Password).GetNetworkCredential().Password
        }

        if ( $DoNotRequireNewPassword.IsPresent ) {
            $Body.requires_new_password = $false
        } else {
            $Body.requires_new_password = $true
        }

        $Method = "POST"
        $Route = "s/default/cmd/sitemgr" # Creating a user requires a site. We use the default site here, because it's always present

        if ( $PSCmdlet.ShouldProcess($Name, "Create new unifi admin") ) {
            $jsonResult = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
        }

        if ($PassThru) {
            [Unifi.User]::new($jsonResult)
        }

    }
}
