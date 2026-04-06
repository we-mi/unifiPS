function New-UnifiSite {
    <#
    .SYNOPSIS
        Create a new unifi site
    .DESCRIPTION
        Create a new unifi site
    .NOTES
        Setting most settings for a unifi site is not supported (yet?) in this cmdlet, but you can use '-PassThru' and pipe the output to 'Set-UnifiSite' to set some settings for a site.
    .EXAMPLE
        PS C:\> New-UnifiSite -Name superior_site
        Will create a new site with the name "superior_site"
    .OUTPUTS
        Returns 'Unifi.Site'-Object when '-PassThru' is set, else nothing
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([Unifi.Site] -or $null)]

    param(
        [Parameter(Mandatory, Position=0)]
        [String]$Name,

        [Parameter()]
        [switch]$PassThru
    )

    process {

        $Body = @{
            cmd = "add-site"
            desc = $Name
        }

        $Method = "POST"
        $Route = "s/default/cmd/sitemgr" # Creating a site requires to use a site api endpoint (why though unifi??). We use the default site here, because it's already there and cannot be deleted

        if ( $PSCmdlet.ShouldProcess($Name, "Create new unifi site") ) {
            $jsonResult = Invoke-UnifiRestCall -Method $Method -Route $Route -Body ($Body | ConvertTo-Json)
        }

        if ($PassThru) {
            [Unifi.Site]::new($jsonResult)
        }
    }
}
