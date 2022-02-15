# AzureSecurityBaseline
Security configuration scripts based on Azure Defender Recommendations. Based on @Cloudneeti script found here: https://github.com/Cloudneeti/os-harderning-scripts/blob/master/WindowsServer2019/CIS_Benchmark_WindowsServer2019_v100.ps1

The referenced script contains several errors including wrong or no CCE Ids, wrong properties, and poorly formed configuration. This script also only aims to satisfy the security recommendations provided by Azure Security Center and gives the Azure Id where applicable.

## Prerequisites
- PowerShell 6+ (though I only tested on PowerShell 7)
- DSC Modules (installation snippet included below)

## How to Use
### For Windows Servers
- Install required modules
```powershell
Install-Module -Name AuditPolicyDsc -Force
Install-Module -Name SecurityPolicyDsc -Force
Install-Module -Name NetworkingDsc -Force
Install-Module -Name PSDesiredStateConfiguration -Force
```
- Login to VM using RDP
- Download/copy PowerShell script to VM
- Run PowerShell script to compile DSC
```powershell
.\AzureSecurity_WindowsServer2019.ps1
```
Script will generate MOF files in the directory.

Run below command to apply baseline configuration
```powershell
Start-DscConfiguration -Path .\AzureSecurity_WindowsServer2019  -Force -Verbose -Wait
```
