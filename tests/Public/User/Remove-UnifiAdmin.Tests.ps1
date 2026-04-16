BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force

    $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

    Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck

    New-UnifiAdmin -Name "to-remove-pipeline"
    New-UnifiAdmin -Name "to-remove-string"
}

Describe "Remove-UnifiAdmin" {

    It "Should not throw when we're deleting a user with a pipeline" {
        { Get-UnifiAdmin -Name 'to-remove-pipeline' | Remove-UnifiAdmin -Confirm:$false } | Should -Not -Throw
    }

    It "Should not find user after removal" {
        Get-UnifiAdmin -Name 'to-remove-pipeline' | Should -BeNullOrEmpty
    }

    It "Should not throw when we're deleting a user with a string" {
        { Get-UnifiAdmin -Name 'to-remove-string' | Remove-UnifiAdmin -Confirm:$false } | Should -Not -Throw
    }

    It "Should not find user after removal" {
        Get-UnifiAdmin -Name 'to-remove-string' | Should -BeNullOrEmpty
    }
}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
