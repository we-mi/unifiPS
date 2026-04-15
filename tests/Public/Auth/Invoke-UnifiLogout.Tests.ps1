BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force
}

Describe "Invoke-UnifiLogout" {

    It "Should login" {
        $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
        $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

        { Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck } | Should -Not -Throw
    }

    It "Should logout" {
        { Invoke-UnifiLogout } | Should -Not -Throw
    }

    It "Should throw when calling an api endpoint while not logged in" {
        { Get-UnifiAdmin } | Should -Throw
    }
}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
