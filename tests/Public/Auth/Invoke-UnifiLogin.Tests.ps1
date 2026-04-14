BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force
}

Describe "Invoke-UnifiLogin" {

    Context "Login behaviour" {

        It "Should throw on invalid credentials" {
            $secureString = "this is totally wrong" | ConvertTo-SecureString -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

            { Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck } | Should -Throw
        }

        It "Should return nothing on successful login" {
            $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

            Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck | Should -BeNullOrEmpty
        }

    }

    Context "Parameter behaviour" {

        It "Should return a valid user-object with -PassThru" {
            $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

            $script:myself = Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck -PassThru

            $myself | Should -BeOfType [Unifi.User]
            $myself.Name | Should -Be $env:UNIFI_USER
        }

        It "User-Object should be the expected user" {
            $script:myself.Name | Should -Be $env:UNIFI_USER
        }

    }

}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
