BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force

    $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

    Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck
}

Describe "Get-UnifiSelf" {

    It "Should return the currently logged in user" {
        $user = Get-UnifiSelf

        $user.Name | Should -Be $env:UNIFI_USER
    }
}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
