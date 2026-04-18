function Set-UnifiAdmin {
    <#
    .SYNOPSIS
        Set information and/or properties for a unifi admin account
    .DESCRIPTION
        Set information and/or properties for a unifi admin account
    .NOTES
        This cmdlet can't update your own user. Use 'Set-UnifiSelf' to update your own user. Blame unifi and their stupid api for it.
    .EXAMPLE
        PS C:\> Set-UnifiAdmin -User another_user -NewName yet_another_user
        Will rename "another_user" to "yet_another_user" if this username is not taken yet
    .EXAMPLE
        PS C:\> Set-UnifiAdmin -User another_user -Password (Read-Host -AsSecureString -Prompt "New Password")
        Will prompt for a new password and set it for "another_user"
    .OUTPUTS
        Returns 'Unifi.User'-Object when '-PassThru' is set, else nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([Unifi.User] -or $null)]

    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="String")]
        [String]$UserName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position=1, ParameterSetName="Object")]
        [Unifi.User]$UserObject,

        [Parameter()]
        [String]$NewName,

        [Parameter()]
        [String]$Email,

        [Parameter()]
        [SecureString]$Password,

        [Parameter()]
        [switch]$RequireNewPassword,

        [Parameter()]
        [switch]$PassThru
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
            cmd = "update-admin"
        }

        if ( [String]::IsNullOrWhiteSpace($NewName) -and [String]::IsNullOrWhiteSpace($Email) -and $null -eq $Password)  {
            Write-Warning "No property was given to update the user '$($UserObject.Name)'. Won't update anything"
        } else {
            $updatedAttributes = New-Object System.Collections.ArrayList

            if ( ![String]::IsNullOrWhiteSpace($NewName) ) {
                $Body.name = $NewName
                $null = $updatedAttributes.Add("Name")
            }

            if ( ![String]::IsNullOrWhiteSpace($Email) ) {
                $Body.email = $Email
                $null = $updatedAttributes.Add("Email")
            }

            if ( $null -ne $Password ) {
                $Body.x_password = [System.Management.Automation.PSCredential]::new("dummy",$Password).GetNetworkCredential().Password
                $null = $updatedAttributes.Add("Password")
            }

            $Method = "POST"
            $Route = "s/default/cmd/sitemgr" # Updating a user requires a site. We use the default site here, because it's already there without reading all sites first

            if ( $PSCmdlet.ShouldProcess($UserObject.Name, "Updating attributes '{0}'" -f ($updatedAttributes -join ', ')) ) {
                $jsonResult = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
            }

            if ($PassThru) {
                Get-UnifiAdmin -Name $UserObject.Name
            }
        }
    }
}
