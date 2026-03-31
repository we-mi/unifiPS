function Invoke-UnifiRestCall {
    <#
    .SYNOPSIS
        Performs an api-request against the unifi controller
    .DESCRIPTION
        Performs an api-request against the unifi controller, checks the result and returns a json-object with the result, if any.
        The json-object can be of type "PSCustomObject" or "Hashtable" (default)
    .EXAMPLE
        PS C:\> Invoke-UnifiRestCall -Method GET -Route "self"
        Retrieves information about the logged in user
    .OUTPUTS
        Returns a json-object on success or throws a hopefully meaningful error message. The json-object can be empty if no data was returned.
    #>
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        [Parameter(Mandatory = $True)]
        [ValidateSet("GET","POST","PUT","DELETE")]
        [string]
        $Method,

        [Parameter(Mandatory = $True)]
        [string]
        $Route,

        # Body for Invoke-RestMethod (will only be applied if $Method is POST, PUT or DELETE)
        [Parameter(Mandatory = $False)]
        [Object]
        $Body
    )

    process {

        if ($null -eq $script:WebSession) {
            Throw "Not connected to a unifi-server! Use 'Invoke-UnifiLogin' first."
        }

        $Splat = @{
            Method = $Method
            Uri = "{0}/{1}" -f $script:BaseUri, $Route
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = $script:Timeout
            WebSession = $script:WebSession
            Verbose = $false
        }

        if ($script:useSkipCertParam) {
            $Splat.SkipCertificateCheck = $true
        }

        if (@("POST","PUT","DELETE") -contains $Method -and $null -ne $Body) {
            if ($Body -is [Hashtable]) {
                $Splat.Body = $Body | ConvertTo-Json
            } else {
                $Splat.Body = $Body
            }
        }

        Write-Debug ("Calling {0} [{1}]" -f $Splat.Uri, $Splat.Method)

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
            Write-Debug ("Request to '{0}' finished with 'ok' status. Returning data" -f $Route)
        } else {
            switch ( $apiResult.meta.msg ) {
                "api.err.Invalid" {
                    $reason = "Invalid credentials"
                }

                "api.err.LoginRequired" {
                    $reason = "Not logged in"
                }

                "api.err.NoSiteContext" {
                    $reason = "No site given or invalid api route"
                }

                default {
                    $reason = "Unknown"
                }
            }
            $reason = "{0} [{1}]" -f $reason, $apiResult.meta.msg
            Throw "Request to '{0}' failed with http statuscode {1}! (Reason: {2})" -f $Splat.Uri, $httpStatusCode, $reason
        }

        return $apiResult.data
    }
}
