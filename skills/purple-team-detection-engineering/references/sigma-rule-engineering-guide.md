# Sigma Rule Engineering Standards & Syntax

## Key Fields in Sigma HQ Spec
```yaml
title: Descriptive rule title
id: UUIDv4
status: stable | test | experimental
description: Concise behavioral description
references:
  - https://attack.mitre.org/techniques/T...
author: Detection Engineering Team
date: 2026-09-01
logsource:
  category: process_creation | network_connection | pipe_creation
  product: windows | linux | macos
detection:
  selection:
    Image|endswith: '\mimikatz.exe'
    CommandLine|contains: 'sekurlsa::logonpasswords'
  condition: selection
falsepositives:
  - Authorized red team exercises
level: high | critical
tags:
  - attack.credential_access
  - attack.t1003.001
```
