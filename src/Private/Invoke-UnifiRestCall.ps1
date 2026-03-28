function Invoke-UnifiRestCall {
    [CmdletBinding()]
    [OutputType([Object])]

    param(
        # HTTP Method
        [Parameter(Mandatory = $True)]
        [ValidateSet("GET","POST","PUT","DELETE")]
        [string]
        $Method,

        # REST route (URI)
        [Parameter(Mandatory = $True)]
        [string]
        $Route,

        # Body for Invoke-RestMethod (will only be applied if $Method is POST, PUT or DELETE)
        [Parameter(Mandatory = $False)]
        [Object]
        $Body,

        # Custom Parameters for Invoke-RestMethod
        [Parameter(Mandatory = $False)]
        [Object]
        $CustomRestParams
    )

    process {
        $restParams = @{
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = $script:Timeout
            Uri = $($script:BaseUri) + "/" + $Route
            WebSession = $Script:WebSession
            Method = $Method
            Verbose = $false
        }

        if ($script:useSkipCertParam) {
            $restParams.SkipCertificateCheck = $true
        }

        if ($CustomRestParams) {
            $restParams = $CustomRestParams
        }

        if (@("POST","PUT","DELETE") -contains $Method) {
            $restParams.Body = $Body
        }

        Write-Verbose "Calling $($restParams.Uri) [$($restParams.Method)]"
        try {
            $json = Invoke-RestMethod @restParams
        } catch [System.Net.WebException] {
            $json = $_.ErrorDetails | ConvertFrom-Json
            $ErrorCode = $json.meta.msg
            Write-Error "Error while accessing rest endpoint '$Route' ($Method): $ErrorCode"
        } catch {
            Write-Error "Other error while accessing rest endpoint '$Route' ($Method): $_"
        } finally {
            if ($json) {
                $json
            }

            if ($restParams.SessionVariable) {
                $script:WebSession = $WebSession
            }
        }
    }
}
