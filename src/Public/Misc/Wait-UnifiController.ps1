function Wait-UnifiController {
    <#
    .SYNOPSIS
        Will wait for the unifi controller at the specified URL to become available
    .DESCRIPTION
        Will wait for the unifi controller at the specified URL to become available
        Will wait indefinitely by default, you can pass a timeout value in seconds.
        When the timeout is over and the unifi controller is not available yet then $False is returned, otherwise $True
    .NOTES
        This cmdlet will just wait for the applicance to fully start after the service was already started.
        The web server port must be open and the controller must respond with valid json for this cmdlet to work. Otherwise it will throw an error.

        If you are sure that the server will come up in a short amount of time and listens on the port you can pass -WaitForPort to also wait for the TCP connection to be established
        The internal timeout for the web request is three seconds, so a lower timeout together with -WaitForPort does not make sense.

        Using verbose will bring up some more messages
    .EXAMPLE
        PS C:\> Wait-UnifiController -Server https://localhost:8443
        Will wait endlessly for the server to be started. When the server was started successfully, $True is returned.
    .EXAMPLE
        PS C:\> Wait-UnifiController -Server https://localhost:8443 -Timeout 60
        Will wait one minute for the server to be started and returns $True or $False depending on the outcome
    .EXAMPLE
        PS C:\> Wait-UnifiController -Server https://localhost:8443 -Timeout 60 -WaitForPort
        Will wait one minute for the server to be started and returns $True or $False depending on the outcome. Will also wait for the underlying TCP connection to be established
    .OUTPUTS
        Returns $True when the server is available, or $False when the server was not available after the timeout was reached
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param(
        # Uri of the UniFi Server
        [Parameter(
            Mandatory = $true
        )]
        [string]
        $Server,

        # Timeout in seconds
        [Parameter(
            Mandatory = $false
        )]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Timeout = -1,

        [Parameter()]
        [switch]$SkipCertificateCheck,

        [Parameter()]
        [switch]$WaitForPort
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

        $Splat = @{
            Method = "POST"
            Uri = "{0}/status" -f $Server
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = 3
            Verbose = $False
        }

        if ($script:useSkipCertParam) {
            $Splat.SkipCertificateCheck = $true
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()

        do {
            try {
                $result = Invoke-WebRequest @Splat
                $apiResult = $result.Content | ConvertFrom-Json
                $httpStatusCode = $result.StatusCode

                if ($apiResult.meta.rc -eq "ok" -and $apiResult.meta.up -eq $True) {
                    $timer.Stop()
                    Write-Verbose ("Server is now available after waiting for {0} seconds" -f $timer.Elapsed.TotalSeconds.ToString('0') )

                    return $True
                } else {
                    Write-Verbose ("Server not up yet after {0} seconds (reason: {1} - {2})" -f $timer.Elapsed.TotalSeconds.ToString('0'), $apiResult.meta.app_context_status, $apiResult.meta.app_context_message )
                }
            } catch [System.Net.Sockets.SocketException] {
                if ($WaitForPort.IsPresent) {
                    Write-Verbose ("Could not connect to web server after {0} seconds (yet), but we will try again because of '-WaitForPort'-Parameter" -f $timer.Elapsed.TotalSeconds.ToString('0') )
                } else {
                    Throw "Connection refused to {0}" -f $Splat.Uri
                }
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

            if ($Timeout -ne -1 -and $timer.Elapsed.TotalSeconds -ge $Timeout) {
                $timer.Stop()
                Write-Verbose ("Timeout of {0} seconds was reached while waiting for unifi controller to become available. Giving up!" -f $timer.Elapsed.TotalSeconds.ToString('0') )

                return $False
            }

            Start-Sleep -Seconds 1
        } while ($True)
    }
}
