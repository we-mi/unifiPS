BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force

    $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

    Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck

    $dummyPass = "dummy" | ConvertTo-SecureString -AsPlainText -Force
    New-UnifiAdmin -Name "to-edit-pipeline" -Password $dummyPass -Confirm:$false
    New-UnifiAdmin -Name "to-edit-string" -Password $dummyPass -Confirm:$false
}

Describe "Set-UnifiAdmin" {

    It "Should throw when no property was given" {
        { Set-UnifiAdmin -UserName 'to-edit-string' -Confirm:$false } | Should -Throw
    }

    It "Should not throw when we're editing a user with a pipeline" {
        { Get-UnifiAdmin -Name 'to-edit-pipeline' | Set-UnifiAdmin -NewName "to-edit-pipeline-new" -Email "somethingsomethingpipeline@something.something" -Password $dummyPass -Confirm:$false } | Should -Not -Throw
    }

    It "Should not throw when we're editing a user with a string" {
        { Set-UnifiAdmin -UserName "to-edit-string" -NewName "to-edit-string-new" -Email "somethingsomethingstring@something.something" -Password $dummyPass -Confirm:$false } | Should -Not -Throw
    }

    It "Should return a unifi user object with -PassThru" {
        $user = Get-UnifiAdmin -Name 'to-edit-string-new' | Set-UnifiAdmin -Password $dummyPass -Confirm:$false -PassThru

        $user | Should -BeOfType [Unifi.User]
    }

    It "Should find renamed user" {
        Get-UnifiAdmin -Name 'to-edit-pipeline-new' | Should -BeOfType [Unifi.User]
    }

    It "Should have a new email" {
        Get-UnifiAdmin -Name 'to-edit-pipeline-new' | Select-Object -ExpandProperty Email | Should -Be "somethingsomethingpipeline@something.something"
    }

    It "Should process multiple objects through a pipeline" {
        { Get-UnifiAdmin | Set-UnifiAdmin -Password $dummyPass -Confirm:$false } | Should -Not -Throw
    }
}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
