BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force
}

Describe "Wait-UnifiController" {

    It "Should return true when unifi controller is available" {
        Wait-UnifiController -Server $env:UNIFI_URI -Timeout 10 -SkipCertificateCheck | Should -BeTrue
    }

    It "Should throw when used with non available web server" {
        { Wait-UnifiController -Server http://localhost:1234 -Timeout 10 -SkipCertificateCheck } | Should -Throw
    }

    It "Should wait when used with non available web server and -WaitForPort param" {
        Measure-Command { Wait-UnifiController -Server http://localhost:1234 -Timeout 10 -SkipCertificateCheck -WaitForPort } | Select-Object -ExpandProperty TotalSeconds | Should -BeGreaterOrEqual 10
    }
}

AfterAll {
    Remove-Module unifiPS
}
