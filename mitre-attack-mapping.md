# MITRE ATT&CK Coverage Map

Ten detections spanning six ATT&CK tactics. Each rule is provided in Sigma
(portable), Splunk SPL, and Sentinel KQL.

| # | Detection | Tactic | Technique | Data Source | Severity |
|---|-----------|--------|-----------|-------------|----------|
| 01 | PowerShell encoded command | Execution | T1059.001 | Process creation / Sysmon 1 | High |
| 02 | LSASS memory access | Credential Access | T1003.001 | Process access / Sysmon 10 | High |
| 03 | Scheduled task creation | Persistence / Execution | T1053.005 | Process creation / Sysmon 1 | Medium |
| 04 | Registry Run key persistence | Persistence | T1547.001 | Registry set / Sysmon 13 | Medium |
| 05 | Remote thread injection | Defense Evasion / Priv Esc | T1055 | Create remote thread / Sysmon 8 | Medium |
| 06 | Failed-logon brute force | Credential Access | T1110 | Windows Security 4625 | Medium |
| 07 | AWS root console login | Priv Esc / Persistence | T1078.004 | CloudTrail | High |
| 08 | Shadow copy deletion | Impact | T1490 | Process creation / Sysmon 1 | High |
| 09 | certutil download | Command & Control | T1105 | Process creation / Sysmon 1 | High |
| 10 | Regsvr32 Squiblydoo | Defense Evasion | T1218.010 | Process creation / Sysmon 1 | High |

## Tactic coverage

- **Execution** — T1059.001
- **Persistence** — T1053.005, T1547.001, T1078.004
- **Privilege Escalation** — T1055, T1078.004
- **Defense Evasion** — T1055, T1218.010, (T1027 via encoded PowerShell)
- **Credential Access** — T1003.001, T1110
- **Command and Control** — T1105
- **Impact** — T1490

## How to generate matching telemetry (free)

- **Atomic Red Team** (`Invoke-AtomicTest`) — run the atomics for each technique
  above on a lab VM with Sysmon installed.
- **Splunk BOTS v3** dataset — pre-recorded attack data for Splunk practice.
- **EVTX-ATTACK-SAMPLES** (sbousseaden on GitHub) — ready-made EVTX files you can
  import without running anything.
- **Sysmon config** — use SwiftOnSecurity or Olaf Hartong's modular config.
