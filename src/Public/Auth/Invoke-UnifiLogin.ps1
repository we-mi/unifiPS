function Invoke-UnifiLogin {
    <#
    .SYNOPSIS
        Makes a RestMethod request to the unifi api, which will hopefully login the given user
    .DESCRIPTION
        Makes a RestMethod request to the unifi api, which will hopefully login the given user
        Credentials can be directly used with $Credentials-Parameter (you will be asked for credentials if this parameter is omitted).
        If the login succeeds a WebSession is saved to $Script:WebSession

        A timeout can be specified for the webrequest
    .EXAMPLE
        PS C:\> Invoke-UnifiLogin -Uri https://localhost:8443/api -Timeout 5
        Logs in to the unifi server at the specified address and wait max. 5 seconds
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param(
        # Uri of the UniFi Server
        [Parameter(
            Mandatory = $true
        )]
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
        $Timeout= 5
    )

    process {
        $script:BaseUri = $Uri
        $script:Timeout = $Timeout
        $Script:WebSession = $null

        $TestSkipCertParam = (Get-Command Invoke-RestMethod).Parameters.SkipCertificateCheck
        if ($TestSkipCertParam) { # Parameter to skip cert is available, so why not use it
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
            } catch {}
        }

        if (!($Credential)) {
            $Credential = (Get-Credential -Message "Login for UniFi-Controller $($script:BaseUri)")
        }
        $Body = @{ "username" = $Credential.UserName; "password" = $Credential.GetNetworkCredential().Password } | ConvertTo-JSON

        $restParams = @{
            Headers = @{"charset"="utf-8";"Content-Type"="application/json"}
            TimeoutSec = $script:Timeout
            Uri = $($script:BaseUri) + "/api/login"
            SessionVariable = "WebSession"
            Verbose = $false
            Method = "Post"
        }

        if ($script:useSkipCertParam) {
            $restParams.SkipCertificateCheck = $true
        }

        $jsonResult = Invoke-UnifiRestCall -Method POST -Route "login" -Body $Body -CustomRestParams $restParams

        $Credential = $null
        $Body = $null

        if ($jsonResult.meta.rc -eq "ok") {
            Write-Verbose "Login to Unifi-Controller successful"
            return $True
        } else {
            Write-Error "Login to Unifi-Controller failed"
            return $False
        }
    }
}
