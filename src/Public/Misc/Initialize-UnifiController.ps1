function Initialize-UnifiController {
    <#
    .SYNOPSIS
        Prepares the unifi controller for it's first use
    .DESCRIPTION
        Prepares the unifi controller for it's first use
        Sets a name, a password and a mail-address like one would in the web-interface

        Additionally you can set some other settings which are not configurable through the web interface during the setup-phase. See parameters for more info. The default values for these parameters reflects the default values which the web interface chooses
    .NOTES
        The controller must not be initialized beforehand, and you need to login with "Invoke-UnifiLogin" to be able to use most other cmdlets from this module.

        Creating a cloud account is currently not implemented.

        Using an email-address with only a toplevel-domain (like "admin@localhost" is not supported through the webinterface, but it works fine through the api :>)
    .EXAMPLE
        PS C:\> Initialize-UnifiController -Server https://localhost:8443 -Credential (Get-Credential) -Email "admin@localhost"

        Will use the given credentials and the email-address to setup the server.
    .OUTPUTS
        Return nothing, but will throw an error if the setup could not be completed.
    #>
    [CmdletBinding()]
    [OutputType($null)]

    param(
        # Uri of the UniFi Server
        [Parameter(
            Mandatory = $true
        )]
        [string]
        $Server,

        # Login credentials
        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [String]
        $Email,

        [Parameter(Mandatory)]
        [String]
        $ControllerName,

        [Parameter()]
        [Boolean]
        $AutoBackup = $True,

        [Parameter()]
        [Boolean]
        $BackupToCloud = $True,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $SSHCredentials,

        # Timeout in seconds
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Timeout= 5,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    process {

        if ($SkipCertificateCheck) {
            Write-Verbose "You requested to ignore server-certificates. Check which method we need to use"
            $TestSkipCertParam = (Get-Command Invoke-RestMethod).Parameters.SkipCertificateCheck
            if ($TestSkipCertParam) { # Parameter to skip cert is available, so why not use it
                Write-Verbose "Invoke-RestMethod has a 'SkipCertificateCheck'-Parameter. Use it"
                $script:useSkipCertParam = $true
            } else { # Parameter to skip cert is not available, try a workaround
                try {
                    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                    Write-Verbose "Invoke-RestMethod does not have a 'SkipCertificateCheck'-Parameter. Use CertificatePolicy-Method"
                } catch {
                    Write-Warning "'SkipCertificateCheck' is enabled, but we could not set the CertificatePolicy"
                }
            }
        }

        # most api calls will respond with 'api.err.LoginRequired' when the server is already configured and you didn't pass login credentials. We will use this to find out if we need to configure the server or do nothing
        try {
            $null = Invoke-UnifiRestCall -Method Post -Route "stat/sysinfo" -IgnoreWebSession -BaseUri $Server
        } catch {
            if ( $_.Exception.Message -like '*api.err.LoginRequired*' ) {
                Write-Verbose "Server is already configured. Do nothing"
                return $null
            } else {
                Throw $_
            }
        }

        # we need to make several calls for setting up the unifi controller for it's first use
        #
        # 1. POST https://localhost:8443/api/cmd/sitemgr -> Adding the admin account
        # 2. POST https://localhost:8443/api/set/setting/super_identity -> setting the name of the controller
        # 5. POST https://localhost:8443/api/set/setting/super_mgmt -> setting auto backup
        # 6. POST https://localhost:8443/api/set/setting/mgmt -> setting ssh settings for default site
        # 7. POST https://localhost:8443/api/cmd/system -> telling unifi that the setup is complete
        #
        # We already have some cmdlets to configure some of these settings, but they require authentication (through 'Invoke-UnifiRestCall')


        # Step 1: Create the default admin account
        $Body = @{
            cmd         = 'add-default-admin'
            name        = $Credential.UserName
            x_password  = $Credential.GetNetworkCredential().Password
        }
        if ( -not [String]::IsNullOrWhiteSpace($Email) ) {
            $Body.email = $Email
        }
        Invoke-UnifiRestCall -Method Post -Route "cmd/sitemgr" -IgnoreWebSession -BaseUri $Server -Body $Body

        # Step 2: Set the name of the controller
        $Body = @{
            name = $ControllerName
        }
        $null = Invoke-UnifiRestCall -Method Post -Route "set/setting/super_identity" -IgnoreWebSession -BaseUri $Server -Body $Body

        # Step 3: Setting auto-backup settings
        $Body = @{
            autobackup_enabled        = $AutoBackup
            backup_to_cloud_enabled   = $BackupToCloud
        }
        $null = Invoke-UnifiRestCall -Method Post -Route "set/setting/super_mgmt" -IgnoreWebSession -BaseUri $Server -Body $Body

        # Step 4: Setting ssh settings for default site (use the name from $Credential and randomize the password, when no credentials were given through parameter. This is the same the web interface would do)
        if ($null -eq $SSHCredentials) {
            $Body = @{
                x_ssh_username = $Credential.UserName
                x_ssh_password = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})
            }
        } else {
            $Body = @{
                x_ssh_username = $SSHCredential.UserName
                x_ssh_password = $SSHCredential.GetNetworkCredential.Password()
            }
        }
        $null = Invoke-UnifiRestCall -Method Post -Route "set/setting/mgmt" -IgnoreWebSession -BaseUri $Server -Body $Body

        # Step 7: Finish the setup
        $Body = @{
            cmd         = 'get-installed'
        }
        Invoke-UnifiRestCall -Method Post -Route "cmd/system" -IgnoreWebSession -BaseUri $Server -Body $Body -ReturnWithMetadata
    }
}
