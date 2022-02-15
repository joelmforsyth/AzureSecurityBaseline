<#
.SYNOPSIS
    DSC script to harden Windows Server 2019 VM baseline policies.
.DESCRIPTION
    This script aims to harden Windows Server 2019 VM baseline policies using Desired State Configurations (DSC) based on Azure security recommendations.
.NOTE
    https://docs.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows
.EXAMPLE
    
    .\AzureSecurity_WindowsServer2019.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\AzureSecurity_WindowsServer2019  -Force -Verbose -Wait
#>

# Configuration Definition
Configuration AzureSecurity_WindowsServer2019 {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {
        AccountPolicy AccountPolicies 
        {
            Name  = 'PasswordPolicies'

            # CceId: CCE-36534-6
            # DataSource: Security Policy
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length = '14'

            # CceId: CCE-37073-4
            # DataSource: Security Policy
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age = '2'

            # CceId: CCE-37166-6
            # DataSource: Security Policy
            #  Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history = '24'

        }

        # CceId: CCE-37741-6
        # DataSource: Audit Policy
        # Ensure 'Audit Credential Validation' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Credential Validation (Success)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: AZ-WIN-00111
        # DataSource: Audit Policy
        # Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-36322-6
        # DataSource: Audit Policy
        # Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: AZ-WIN-00182
        # DataSource: Audit Policy
        # Ensure 'Audit PNP Activity' is set to 'Success'
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Plug and Play Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # CceId: CCE-36144-4
        # DataSource: Audit Policy
        # Ensure 'Audit Security System Extension' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
           Name      = 'Security System Extension'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
           Name      = 'Security System Extension'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }

        # CceId: AZ-WIN-00026
        # DataSource: Audit Policy
        # Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
      
        # CceId: CCE-37617-8
        # DataSource: Audit Policy
        # Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
           Name      = 'Removable Storage'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
           Name      = 'Removable Storage'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }

        # CceId: CCE-36267-3
        # DataSource: Audit Policy
        # Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
           Name      = 'Sensitive Privilege Use'
           AuditFlag = 'Success'
           Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: CCE-37133-6
        # DataSource: Audit Policy
        # Ensure 'Audit Account Lockout' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: AZ-WIN-00113
        # DataSource: Audit Policy
        # Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # CceId: AZ-WIN-00130
        # DataSource: Registry Policy
        # Ensure 'Allow Cortana above lock screen' is set to 'Disabled'
        Registry 'AllowCortanaAboveLock' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortanaAboveLock'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: AZ-WIN-00131
        # DataSource: Registry Policy
        # Ensure 'Allow Cortana' is set to 'Disabled'
        Registry 'AllowCortana' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowCortana'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: AZ-WIN-00168
        # DataSource: Registry Policy
        # Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'AllowInputPersonalization' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
            ValueName = 'AllowInputPersonalization'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38354-7
        # DataSource: Registry Policy
        # Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
        Registry 'MSAOptional' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'MSAOptional'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00133
        # DataSource: Registry Policy
        # Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
        Registry 'AllowSearchToUseLocation' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowSearchToUseLocation'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: AZ-WIN-00169
        # DataSource: Registry Policy
        # Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
        Registry 'AllowTelemetry' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
        }
       
        # CceId: CCE-36000-8
        # DataSource: Registry Policy
        # Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
        Registry 'DisableRunAs' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36223-6
        # DataSource: Registry Policy
        # Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
        Registry 'DisablePasswordSaving' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38353-9
        # DataSource: Registry Policy
        # Ensure 'Do not display network selection UI' is set to 'Enabled'
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00140
        # DataSource: Registry Policy
        # Ensure 'Do not show feedback notifications' is set to 'Enabled'
        Registry 'DoNotShowFeedbackNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00171
        # DataSource: Registry Policy
        # Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37346-4
        # DataSource: Registry Policy
        # Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
        Registry 'EnableAuthEpResolution' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'EnableAuthEpResolution'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37534-5
        # DataSource: Registry Policy
        # Ensure 'Do not display the password reveal button' is set to 'Enabled'
        Registry 'DisablePasswordReveal' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
            ValueName = 'DisablePasswordReveal'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37948-7
        # DataSource: Registry Policy
        # Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeApplication' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: AZ-WIN-00138
        # DataSource: Registry Policy
        # Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'
        Registry 'BlockUserFromSh owingAccountDetailsOnSignin' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37912-3
        # DataSource: Registry Policy
        # Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
        Registry 'DriverLoadPolicy' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName = 'DriverLoadPolicy'
            ValueType = 'DWord'
            ValueData = '3'
        }
        
        # CceId: CCE-37281-3
        # DataSource: Registry Policy
        # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowToGetHelp'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-35859-8  
        # DataSource: Registry Policy
        # Ensure 'Configure Windows SmartScreen' is set to 'Enabled' 
        Registry 'EnableSmartScreen' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38318-2
        # DataSource: Registry Policy
        # Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37856-2
        # DataSource: Audit Policy
        # Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
           Name      = 'User Account Management'
           AuditFlag = 'Failure'
           Ensure    = 'Present'
        }
        
        # CceId: AZ-WIN-00177
        # DataSource: Registry Policy
        # Enable 'Scan removable drives' by setting DisableRemovableDriveScanning (REG_DWORD) to 0
        Registry 'DisableRemovableDriveScanning' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
            ValueName = 'DisableRemovableDriveScanning'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37636-8
        # DataSource: Registry Policy
        # Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
        Registry 'NoAutoplayfornonVolume' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00126
        # DataSource: Registry Policy
        # Enable 'Send file samples when further analysis is required' for 'Send Safe Samples'
        Registry 'SubmitSamplesConsent' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet'
            ValueName = 'SubmitSamplesConsent'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37929-7
        # DataSource: Registry Policy
        # Ensure 'Always prompt for password upon connection' is set to 'Enabled'
        Registry 'fPromptForPassword' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37567-5
        # DataSource: Registry Policy
        # Ensure 'Require secure RPC communication' is set to 'Enabled'
        Registry 'fEncryptRPCTraffic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37526-1
        # DataSource: Registry Policy
        # Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        Registry 'MaxSizeSetupLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-37695-4
        # DataSource: Registry Policy
        # Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
        Registry 'MaxSizeSecurityLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '196700'
        }

        # CceId: AZ-WIN-00172
        # DataSource: Registry Policy
        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_PersonalFirewallConfig' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_PersonalFirewallConfig'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38002-2
        # DataSource: Registry Policy
        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38348-9
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
        Registry 'NoLockScreenSlideshow' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38347-1
        # DataSource: Registry Policy
        # Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' 
        Registry 'NoLockScreenCamera' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenCamera'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37126-0
        # DataSource: Registry Policy
        # Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
        Registry 'DisableEnclosureDownload' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37835-6
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinServerSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinServerSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # CceId: CCE-36173-3
        # DataSource: Registry Policy
        # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
        Registry 'LmCompatibilityLevel' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'LmCompatibilityLevel'
            ValueType = 'DWord'
            ValueData = '5'
        }

        # CceId: CCE-36077-6
        # DataSource: Registry Policy
        # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)
        Registry 'RestrictAnonymous' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictAnonymous'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38217-6
        # DataSource: Registry Policy
        # Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
        Registry 'NoAutorun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutorun'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36494-3
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
        Registry 'FilterAdministratorToken' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'FilterAdministratorToken'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36864-7
        # DataSource: Registry Policy
        # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
        Registry 'ConsentPromptBehaviorUser' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'ConsentPromptBehaviorUser'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37553-5 
        # DataSource: Registry Policy
        # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
        Registry 'NTLMMinClientSec' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            ValueName = 'NTLMMinClientSec'
            ValueType = 'DWord'
            ValueData = '537395200'
        }

        # CceId: CCE-36146-9 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Registry 'OutboundActionDefault' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
            ValueName = 'OutboundActionDefault'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36062-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00145 
        # DataSource: Registry Policy
        # Ensure 'Turn off multicast name resolution' is set to 'Enabled' 
        Registry 'EnableMulticast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMulticast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37163-3 
        # DataSource: Registry Policy
        # Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
        Registry 'ExitOnMSICW' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName = 'ExitOnMSICW'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36092-5
        # DataSource: Registry Policy
        # Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
        # JMF: Modified from 1, looks like typo.
        Registry 'MaxSizeSystemLog' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName = 'MaxSize'
            ValueType = 'DWord'
            ValueData = '32768'
        }

        # CceId: CCE-35893-7
        # DataSource: Registry Policy
        # Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' 
        Registry 'DisableLockScreenAppNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-36875-3
        # DataSource: Registry Policy
        # Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
        Registry 'NoDriveTypeAutoRun' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'DWord'
            ValueData = '255'
        }

        # CceId: CCE-36877-9
        # DataSource: Security Policy
        # Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
        }

        # CceId: CCE-37146-8
        # DataSource: Security Policy
        # Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = 'Guests'
        }

        # CceId: CCE-36867-0 
        # DataSource: Security Policy
        # Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'Guests, Local account'
        }

        # CceId: CCE-37659-0
        # DataSource: Security Policy
        # Ensure 'Allow log on locally' is set to 'Administrators'
        UserRightsAssignment Allowlogonlocally {
            Policy   = 'Allow_log_on_locally'
            Identity = 'Administrators' 
        }

        # CceId: CCE-36923-1
        # DataSource: Security Policy
        # Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Guests'
        }

        # CceId: CCE-38040-2
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'AllowLocalIPsecPolicyMergeDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38041-0 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
        Registry 'OffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
            ValueName = 'OffNotifications'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38239-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38332-3
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-37954-5
        # DataSource: Security Policy
        # Ensure 'Deny access to this computer from the network' is set to 'Guests' (DC only)
        UserRightsAssignment  Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'Guests'
        }

        # CceId: CCE-36063-6
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
        Registry 'AllowLocalIPsecPolicyMergePrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37621-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No''
        Registry 'DisableNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37862-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)
        Registry 'OutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'OutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36268-1
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        Registry 'AllowLocalIPsecPolicyMergePublic' {
            Ensure       = 'Present'
            Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName    = 'AllowLocalIPsecPolicyMerge'
            ValueType    = 'DWord'
            ValueData    = '0'
        }
        
        # CceId: CCE-38043-6
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
        Registry 'turuoffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'turuoffNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00089
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcastPrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00090
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcastPublic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: AZ-WIN-00184
        # DataSource: Security Policy
        # Ensure 'Bypass traverse checking' is set to 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        UserRightsAssignment Bypasstraversechecking {
            Policy   = 'Bypass_traverse_checking'
            Identity = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
        }

        # CceId: CCE-35818-4
        # DataSource: Security Policy
        # Ensure 'Access  this computer from the network' is set to 'Administrators, Authenticated Users' (DC only)
        UserRightsAssignment  Accessthiscomputerfromthenetwork {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = 'Administrators, Authenticated Users'
        }

        # CceId: AZ-WIN-00088
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Allow unicast response' is set to 'No'
        Registry 'DisableUnicastResponsesToMulticastBroadcast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38328-1
        # DataSource: Security Policy
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy   = 'Shut_down_the_system'
            Identity = 'Administrators'
        }

        # CceId: AZ-WIN-00185
        # DataSource: Security Policy
        # Ensure 'Increase a process working set' is set to 'Administrators, Local Service'
        UserRightsAssignment Increaseaprocessworkingset {
            Policy   = 'Increase_a_process_working_set'
            Identity = 'Administrators, Local Service'
        }

        
        SecurityOption AccountSecurityOptions 
        {
            Name = 'AccountSecurityOptions'

            # CceId: CCE-36056-0
            # DataSource: Registry Policy
            # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
            Interactive_logon_Do_not_display_last_user_name = 'Enabled' 
        
            # CceId: CCE-36325-9
            # DataSource: Registry Policy
            # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

            # CceId: AZ-WIN-00155
            # DataSource: Registry Policy
            # Ensure 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' is set to 'Enabled'
            System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'

            # CceId: CCE-35988-5
            # DataSource: Registry Policy
            # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

            # CceId: CCE-37864-6
            # DataSource: Registry Policy
            # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

            # CceId: CCE-38341-4
            # DataSource: Registry Policy
            # Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
             Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'

            # CceId: AZ-WIN-00120
            # DataSource: Registry Policy
            # Ensure 'Devices: Allow undock without having to log on' is set to 'Disabled'
            # JMF: Modified from 'Enabled', possible typo
            Devices_Allow_undock_without_having_to_log_on = 'Disabled'

            # CceId: CCE-37029-6
            # DataSource: Registry Policy
            # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode  = 'Prompt for consent on the secure desktop'
        }
    }
}
AzureSecurity_WindowsServer2019
