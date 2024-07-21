
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [String]$Server,

    [Parameter(Mandatory)]
    [String]$Username,

    [Parameter(Mandatory)]
    [String]$Password
)

Get-ChildItem -Path (Join-Path $PSScriptRoot 'tests') -Recurse -Filter "*.Test.ps1" | ForEach-Object {
    $pesterContainer = New-PesterContainer -Path $_.Fullname -Data @{
        Server = $Server
        Username = $Username
        Password = $Password
    }

    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Output.Verbosity = "Detailed"
    $pesterConfig.Run.PassThru = $False
    $pesterConfig.Run.Container = $pesterContainer

    Invoke-Pester -Configuration $pesterConfig
}
