BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force
}

Describe "Initialize-UnifiController" {

        It "Should throw when unifi controller is already configured" {
            $secureString = "this is totally wrong" | ConvertTo-SecureString -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

            { Initialize-UnifiController -Server $env:UNIFI_URI -Credential $cred -Email "nonsense@localhost" -SkipCertificateCheck } | Should -Throw
        }
}

AfterAll {
    Remove-Module unifiPS
}
