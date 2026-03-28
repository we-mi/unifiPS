function Remove-UnifiFirewallRule {
    <#
    .SYNOPSIS
        Deletes a firewall rule in a site
    .DESCRIPTION
        Deletes a firewall rule in a site and asks for confirmation
    .EXAMPLE
        PS C:\> Get-UnifiSite "test" | Get-UnifiFirewallRule -RuleName "Allow RDP" | Remove-UnifiFirewallRule -Force
        Removes the firewall rule "Allow RDP" from the site "test" and does not ask for confirmation
    .OUTPUTS
        Returns $True on Success
        Returns $False on Failure
    #>
    [CmdletBinding()]
    [OutputType([Boolean])]

    param(
        # Name of the site (Unifi's internal name is used, not the name visible in the web interface)
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true )]
        [String]
        $SiteName,

        # ID of the Firewall group to be deleted
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $RuleID,

        # Do not ask for confirmation
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    process {
        try {
            $fwRule = Get-UnifiFirewallRule -SiteName $SiteName | Where-Object { $_.RuleID -eq $RuleID }

            if ($fwRule) {
                if (!$Force) {
                    do {
                        $answer = Read-Host -Prompt "Do you really want to delete the firewall rule '$($fwRule.RuleName)' (ID: $($RuleID))? (y/N): "
                    } while($answer -ne "y" -and $answer -ne "n" -and $answer -ne "")

                    if ($answer -eq "" -or $answer -eq "n") {
                        Write-Verbose "Deletion of firewall rule '$($fwRule.RuleName)' (ID: $($RuleID)) was aborted by user"
                        return $False
                    }

                }
                $jsonResult = Invoke-UnifiRestCall -Method DELETE -Route "api/s/$($SiteName)/rest/firewallrule/$($RuleID)"

                if ($jsonResult.meta.rc -eq "ok") {
                    Write-Verbose "Firewall rule '$($fwRule.RuleName)' successfully deleted for site $SiteName"
                    return $True
                } else {
                    Write-Error "Firewall rule '$($fwRule.RuleName)' was NOT deleted for site $SiteName"
                    return $False
                }
            } else {
                Write-Error "No Firewall rule with ID '$RuleID' was found in site '$SiteName'"
                return $False
            }

        } catch {
            Write-Warning "Something went wrong while removing firewall rule with ID '$($RuleID)' for site '$($SiteName)' ($_)"
        }
    }
}
