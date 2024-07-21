[CmdletBinding()]
param()

process {
    Write-Host -ForegroundColor Magenta "Generating docs"

    Get-Module unifiPS | Remove-Module
    Import-Module (Join-Path $PSScriptRoot "unifiPS\unifiPS.psd1")

    Update-MarkdownHelp .\docs -AlphabeticParamsOrder -UseFullTypeName -Encoding ([System.Text.Encoding]::UTF8)
}
