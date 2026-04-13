function Invoke-UnifiLogin {
    <#
    .SYNOPSIS
        Performs a login request to the unifi-controller
    .DESCRIPTION
        Performs a login request to the unifi-controller and saves a websession for future requests to the api.
    .EXAMPLE
        PS C:\> Invoke-UnifiLogin -Server https://localhost:8443 -SkipCertificateCheck -PassThru
        Tries to login to the unifi controller without checking the ssl certificate and returns information about the own user.
    .OUTPUTS
        Returns an object of type 'Unifi.User' when '-PassThru' is set, else returns nothing
    #>
    [CmdletBinding()]
    [OutputType([Unifi.User] -or $null)]

    param(
        # Uri of the UniFi Server
        [Parameter(
            Mandatory = $true
        )]
        [Alias("Server")]
        [string]
        $Uri,

        # Login credentials
        [Parameter(
            Mandatory = $false
        )]
        [System.Management.Automation.PSCredential]
        $Credential,

        # Timeout in seconds
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Timeout= 5,

        [Parameter()]
        [switch]$SkipCertificateCheck,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        $script:BaseUri = "{0}" -f $Uri
        $script:Timeout = $Timeout
        $Script:WebSession = $null

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

        if (!($Credential)) {
            $Credential = (Get-Credential -Message "Login for UniFi-Controller $($script:BaseUri)")
        }

        $Splat = @{
            Method = "POST"
            Uri = "{0}/api/login" -f $script:BaseUri
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = $script:Timeout
            SessionVariable = "WebSession"
            Body = @{ "username" = $Credential.UserName; "password" = $Credential.GetNetworkCredential().Password } | ConvertTo-JSON
        }; $Credential = $null

        if ($script:useSkipCertParam) {
            $Splat.SkipCertificateCheck = $true
        }

        Write-Verbose ("Calling {0} [{1}]" -f $Splat.Uri, $Splat.Method)

        try {
            $result = Invoke-WebRequest @Splat
            $apiResult = $result.Content | ConvertFrom-Json
            $httpStatusCode = $result.StatusCode
        } catch [System.Net.Sockets.SocketException] {
            Throw "Connection refused to {0}" -f $Splat.Uri
        } catch [Newtonsoft.Json.JsonReaderException] {
            Throw "HTTP-Code {0}; API-Response is not in JSON format: {1}" -f $httpStatusCode, $result
        } catch {
            $errorDetails = $_.ErrorDetails
            $httpStatusCode = $_.Exception.Response.StatusCode.value__
            try {
                $apiResult = $_.ErrorDetails | ConvertFrom-Json
            } catch [Newtonsoft.Json.JsonReaderException] {
                # This might not be a json-string. Throw the error message as it is
                Throw "HTTP-Code {0}; API-Response is not in JSON format: {1}" -f $httpStatusCode, $errorDetails
            }
        }

        if ($apiResult.meta.rc -eq "ok") {
            Write-Verbose "Login to Unifi-Controller successful"
        } else {
            switch ( $apiResult.meta.msg ) {
                "api.err.Invalid" {
                    $reason = "Invalid credentials"
                }

                default {
                    $reason = "Unknown {0}" -f $_
                }
            }
            Throw "Login failed with http statuscode {0}! ({1})" -f $httpStatusCode,$reason
        }

        $script:WebSession = $WebSession
        if ($PassThru) {
            Get-UnifiSelf
        }
    }
}
