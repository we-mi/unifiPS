function Get-UnifiSite {
    <#
    .SYNOPSIS
        Lists sites of a unifi controller
    .DESCRIPTION
        Lists sites of a unifi controller. You can filter by ID, internal name and display name
    .NOTES
        You almost never come in touch with the ID of the site.
        The "InternalName" is what you need to talk to the api and it's also displayed in the url when the site is selected.
        "Name" is what you will see as the actual name of the site (internally handled as the site description)
    .EXAMPLE
        PS C:\> Get-UnifiSite
        List all sites
    .EXAMPLE
        PS C:\> Get-UnifiSite -Name "Default","*Test*"
        Lists the site "default" and all sites which contain "Test" in the display name of the site
    .EXAMPLE
        PS C:\> Get-UnifiSite -InternalName "67itznop"
        Lists the site with the internal name '67itznop'
    .EXAMPLE
        PS C:\> Get-UnifiSite -ID "623e1bf66a5d4f1280160b7e"
        Lists the site with the ID '623e1bf66a5d4f1280160b7e'
    .OUTPUTS
        Returns objects of type 'Unifi.Site'
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    [OutputType([Unifi.Site])]

    param(
        [Parameter(ParameterSetName="ID")]
        [String[]]
        $ID,

        # Used for most API Calls
        [Parameter(ParameterSetName="InternalName")]
        [String[]]
        $InternalName,

        # internally handled as "description"
        [Parameter(ParameterSetName="Name",Position=0)]
        [String[]]
        $Name
    )

    process {
        $jsonResult = Invoke-UnifiRestCall -Method GET -Route "self/sites"

        switch ($PSCmdlet.ParameterSetName) {
            "ID" {
                $tmpList = @()
                foreach($entity in $ID) {
                    $tmpList += $jsonResult | Where-Object { $_._id -like $entity }
                }
                $jsonResult = $tmpList | Sort-Object -Property _id -Unique
            }

            "InternalName" {
                $tmpList = @()
                foreach($entity in $InternalName) {
                    $tmpList += $jsonResult | Where-Object { $_.name -like $entity }
                }
                $jsonResult = $tmpList | Sort-Object -Property _id -Unique
            }

            "Name" {
                $tmpList = @()
                foreach($entity in $Name) {
                    $tmpList += $jsonResult | Where-Object { $_.desc -like $entity }
                }
                $jsonResult = $tmpList | Sort-Object -Property _id -Unique
            }
        }

        foreach ($site in $jsonResult) {
            [Unifi.Site]::new($site)
        }
    }
}
