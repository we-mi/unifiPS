BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force

    $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

    Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck
}

Describe "Get-UnifiAdmin" {

    It "Should not throw when we're logged in" {
        { Get-UnifiAdmin } | Should -Not -Throw
    }

    It "Should return an array" {
        Get-UnifiAdmin | Should -BeOfType [System.Object[]]
    }

    It "Should only contain objects of type [Unifi.User]" {
        Get-UnifiAdmin | ForEach-Object {
            $_ | Should -BeOfType [Unifi.User]
        }
    }

    It "Should return our own user" {
        (Get-UnifiAdmin).Name | Should -Contain $env:UNIFI_USER
    }
}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
