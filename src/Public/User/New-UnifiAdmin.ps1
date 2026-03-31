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

        if ( [String]::IsNullOrWhiteSpace($NewName) -and [String]::IsNullOrWhiteSpace($Email) -and $null -eq $Password)  {
            Write-Warning "No property was given to update the user '$($UserObject.Name)'. Won't update anything"
        } else {
            if ( ![String]::IsNullOrWhiteSpace($NewName) ) {
                $Body.name = $NewName
            }

            if ( ![String]::IsNullOrWhiteSpace($Email) ) {
                $Body.email = $Email
            }

            if ( $null -ne $Password ) {
                $Body.x_password = [System.Management.Automation.PSCredential]::new("dummy",$Password).GetNetworkCredential().Password
            }

            if ( $DoNotRequireNewPassword ) {
                $Body.requires_new_password = $false
            } else {
                $Body.requires_new_password = $true
            }

            $Method = "POST"
            $Route = "s/default/cmd/sitemgr" # Updating a user requires a site. We use the default site here, because it's already there without reading all sites first

            if ( $PSCmdlet.ShouldProcess($UserObject.Name, "Create new unifi admin") ) {
                $jsonResult = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }

            if ($PassThru) {
                [Unifi.User]::new($jsonResult)
            }
        }
    }
}
