$Script:WebSession = $null
$Script:BaseUri = $null
$Script:RestHeaders = $null

# Get public and private function definition files.
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\ -Include *.ps1 -Recurse -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\ -Include *.ps1 -Recurse -ErrorAction SilentlyContinue )

# Dot source the files
Foreach($import in @($Public + $Private)) {
    Try {
        . $import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename

# Load .cs files (contains types)
Get-ChildItem -Path (Join-Path $PSScriptRoot 'Types') -Filter 'Unifi.*.cs' | ForEach-Object {
    $File = $_
    try {
        $null = New-Object ($File.Name -replace '\.cs$')
    } catch {
        Add-Type -Path $File.FullName
    }
}

# Set some aliases for backwards compatibility
Set-Alias -Name Get-UnifiLogin -Value Get-UnifiSelf