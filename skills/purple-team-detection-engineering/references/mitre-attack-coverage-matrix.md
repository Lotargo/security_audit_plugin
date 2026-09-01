# MITRE ATT&CK Telemetry & Coverage Matrix

| ATT&CK ID | Technique Name | Primary Telemetry Source | Recommended Event ID |
| :--- | :--- | :--- | :--- |
| **T1059.001** | PowerShell ScriptBlock Logging | Windows Microsoft-Windows-PowerShell/Operational | Event ID 4104 |
| **T1059.003** | Windows Command Shell | Microsoft-Windows-Security-Auditing | Event ID 4688 (Process Creation) |
| **T1078** | Valid Accounts (Cloud Console) | AWS CloudTrail / Entra ID Sign-ins | `ConsoleLogin`, `UserLoggedIn` |
| **T1003.001** | OS Credential Dumping (LSASS) | Sysmon Process Access / EDR Sensor | Sysmon Event ID 10 (ProcessAccess) |
| **T1047** | Windows Management Instrumentation (WMI) | Microsoft-Windows-WMI-Activity/Operational | Event ID 5861 |
| **T1562.001** | Impair Defenses (Disable Security Tools) | Security Auditing / Sysmon | Event ID 1102 / Sysmon Event ID 1 |
