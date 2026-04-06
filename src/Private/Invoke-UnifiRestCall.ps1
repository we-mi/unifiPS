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

        [Parameter()]
        [string]
        $Prefix = "/api",

        # Body for Invoke-RestMethod (will only be applied if $Method is POST, PUT or DELETE)
        [Parameter(Mandatory = $False)]
        [Object]
        $Body,

        [Parameter()]
        [switch]
        $ReturnWithMetadata
    )

    process {

        if ($null -eq $script:WebSession) {
            Throw "Not connected to a unifi-server! Use 'Invoke-UnifiLogin' first."
        }

        $Splat = @{
            Method = $Method
            Uri = "{0}{1}/{2}" -f $script:BaseUri, $Prefix, $Route
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

                "api.err.NoPermission" {
                    $reason = "No permission"
                }

                "api.err.PasswordsDontMatch" {
                    $reason = "Password mismatch"
                }

                "api.err.IdInvalid" {
                    $reason = "Unknown user"
                }

                "api.err.EmailExisted" {
                    $reason = "Another user uses the same email-address"
                }

                "api.err.InvalidEmail" {
                    $reason = "Invalid Email address"
                }

                "api.err.NameExisted" {
                    $reason = "Another user uses the same name"
                }

                "api.err.NoSiteContext" {
                    $reason = "No site given, site does not exist or invalid api route"
                }

                "api.err.DuplicateSiteName" {
                    $reason = "Site with this internal name already exists"
                }

                "api.err.InvalidAdminPassword" {
                    $reason = "Invalid or empty password"
                }

                "api.err.InvalidIpOrHostname" {
                    $reason = "Invalid IP or Hostname"
                }

                "api.err.InvalidPayload" {
                    $reason = "Invalid Payload"
                }

                "api.err.InvalidSshKey" {
                    $reason = "Invalid SSH Key"
                }

                default {
                    $reason = "Unknown"
                }
            }
            $reason = "{0} [{1}]" -f $reason, $apiResult.meta.msg
            Throw "Request to '{0}' failed with http statuscode {1}! (Reason: {2})" -f $Splat.Uri, $httpStatusCode, $reason
        }

        if ($ReturnWithMetadata.IsPresent) {
            return $apiResult
        } else {
            return $apiResult.data
        }
    }
}
