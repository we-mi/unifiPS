BeforeAll {
    $ProjectRoot = '/home/runner/work/unifiPS/unifiPS'
    Import-Module (Join-Path $ProjectRoot 'src/unifiPS.psd1') -Force

    $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

    Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck

    $newUserName = "newadmin"
    $newUserPassword = "newpassword" | ConvertTo-SecureString -AsPlainText -Force

}

Describe "New-UnifiAdmin" {

    It "Should not throw when creating a new admin" {
        { New-UnifiAdmin -Name $newUserName -Password $newUserPassword -Confirm:$false }  | Should -Not -Throw
    }

    It "Should throw when trying to create the same user again" {
        { New-UnifiAdmin -Name $newUserName -Password $newUserPassword -Confirm:$false }  | Should -Throw
    }

    It "Should list the new admin" {
        Get-UnifiAdmin -Name $newUserName | Select-Object -ExpandProperty Name | Should -Be $newUserName
    }

    It "Should have an empty mail address" {
        Get-UnifiAdmin -Name $newUserName | Select-Object -ExpandProperty Email | Should -BeNullOrEmpty
    }

    It "Should login with the new admin" {
        Invoke-UnifiLogout

        $cred = [System.Management.Automation.PSCredential]::new($newUserName,$newUserPassword)

        { Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck } | Should -Not -Throw

        # restore the previous login
        Invoke-UnifiLogout
        $secureString = $env:UNIFI_PASS | ConvertTo-SecureString -AsPlainText -Force
        $cred = [System.Management.Automation.PSCredential]::new($env:UNIFI_USER,$secureString)

        Invoke-UnifiLogin -Uri $env:UNIFI_URI -Credential $cred -Timeout 10 -SkipCertificateCheck
    }

    It "Should re-create the user after it was deleted (this time with a mail address" {
        Get-UnifiAdmin -Name $newUserName | Remove-UnifiAdmin -Confirm:$false
        { New-UnifiAdmin -Name $newUserName -Password $newUserPassword -Email "user@localhost" -Confirm:$false }  | Should -Not -Throw
    }

    It "Should have the mail address filled" {
        Get-UnifiAdmin -Name $newUserName | Select-Object -ExpandProperty Email | Should -Be "user@localhost"
    }
}

AfterAll {
    Invoke-UnifiLogout
    Remove-Module unifiPS
}
