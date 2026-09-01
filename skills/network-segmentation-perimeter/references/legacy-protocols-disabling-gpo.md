# Legacy Protocol Disablement & Hardening (GPO / Linux)

## Windows GPO Settings

1. **Disable LLMNR**:
   - Path: `Computer Configuration -> Administrative Templates -> Network -> DNS Client`
   - Setting: `Turn off multicast name resolution` -> **Enabled**

2. **Disable NetBIOS over TCP/IP**:
   - Path: `DHCP Scope -> Scope Options -> 043 Vendor Specific Info -> 0x02` (Disabled)
   - Or PowerShell: `Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object { $_.SetTcpipNetbios(2) }`

3. **Require SMB Signing**:
   - Path: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`
   - `Microsoft network server: Digitally sign communications (always)` -> **Enabled**
