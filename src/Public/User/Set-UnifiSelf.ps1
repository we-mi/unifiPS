function Set-UnifiSelf {
    <#
    .SYNOPSIS
        Set information and/or properties for the own admin account
    .DESCRIPTION
        Set information and/or properties for the own admin account
    .NOTES
        This function exists because the underlying API-endpoint for 'Set-UnifiAdmin' cannot update the own user. In addition to this you explicitly need to type your current password for this cmdlet to work.
    .EXAMPLE
        PS C:\> Set-UnifiSelf -Password (Read-Host -AsSecureString -Prompt 'New Password')
        Asks for a new password and set it for the currently logged in user
    .EXAMPLE
        PS C:\> Set-UnifiSelf -Email "newmail@example.org"
        Sets a new mail for the currently logged in user
    .OUTPUTS
        Returns 'Unifi.User'-Object when '-PassThru' is set, else nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([Unifi.User] -or $null)]

    param(
        [Parameter()]
        [String]$Name,

        [Parameter()]
        [String]$Email,

        [Parameter(Mandatory)]
        [SecureString]$CurrentPassword,

        [Parameter()]
        [SecureString]$NewPassword,

        [Parameter()]
        [switch]$RequireNewPassword,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        # get our own unifi.user object
        $UserObject = Get-UnifiSelf

        $Body = @{
            x_oldpassword = [System.Management.Automation.PSCredential]::new("dummy",$CurrentPassword).GetNetworkCredential().Password
        }

        if ( [String]::IsNullOrWhiteSpace($Name) -and [String]::IsNullOrWhiteSpace($Email) -and $null -eq $NewPassword)  {
            Write-Warning "No property was given to update the user '$($UserObject.Name)'. Won't update anything"
        } else {
            $updatedAttributes = New-Object System.Collections.ArrayList

            if ( ![String]::IsNullOrWhiteSpace($Name) ) {
                $Body.name = $Name
                $null = $updatedAttributes.Add("Name")
            }

            if ( ![String]::IsNullOrWhiteSpace($Email) ) {
                $Body.email = $Email
                $null = $updatedAttributes.Add("Email")
            }

            if ( $null -ne $NewPassword ) {
                $Body.x_password = [System.Management.Automation.PSCredential]::new("dummy",$NewPassword).GetNetworkCredential().Password
                $null = $updatedAttributes.Add("Password")
            }

            $Method = "PUT"
            $Route = "self"

            if ( $PSCmdlet.ShouldProcess($UserObject.Name, "Updating attributes '{0}'" -f ($updatedAttributes -join ', ')) ) {
                $null = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }

            if ($PassThru) {
                Get-UnifiSelf
            }
        }
    }
}
