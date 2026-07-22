# Investigation Writeup — INV-01

**Alert:** Suspicious PowerShell Encoded Command Execution
**Technique:** T1059.001 (Command and Scripting Interpreter: PowerShell)
**Severity:** High
**Analyst:** Romeel Bhavsar

---

## 1. Alert summary
The SIEM fired on `powershell.exe` executing with `-enc`. Host `WKS-1042`,
user `jsmith`, parent process `winword.exe`. A Word document spawning an
encoded PowerShell child is a classic maldoc execution chain.

## 2. Triage steps
1. **Decode the payload.** Copy the Base64 blob and decode it (CyberChef
   "From Base64" → "Decode text" / UTF-16LE). Read what the script actually does
   before anything else.
2. **Establish parentage.** Confirm `winword.exe` → `powershell.exe`. Office
   should almost never spawn PowerShell — strong malicious signal.
3. **Pull surrounding process tree** for the host in the same window (Sysmon
   EID 1) to see follow-on activity (downloads, persistence, LSASS access).
4. **Enrich network IOCs.** Any URL/IP in the decoded script → VirusTotal,
   urlscan.io, AbuseIPDB. Note domain age and reputation.
5. **Check for outbound success** — did the host reach the C2? Firewall/proxy
   logs or Sysmon EID 3 (network connection).

## 3. Evidence collected
- Decoded PowerShell (downloader that pulls `stage2.ps1` from a newly
  registered domain).
- Process tree: `winword.exe → powershell.exe -enc → certutil.exe` (pivot to
  detection #09).
- VirusTotal: hosting domain flagged by 8/90 vendors.

## 4. Verdict
**True Positive — confirmed malicious.** Maldoc-initiated download/execution.

## 5. Escalation & response
- Escalate to Tier 2 / IR per playbook.
- **Isolate** `WKS-1042` (EDR network containment).
- Preserve evidence: capture the decoded script, process tree, and the maldoc
  hash. Do not delete — chain of custody for IR.
- Block the C2 domain/IP at proxy and add IOCs to the blocklist.
- Reset `jsmith` credentials; review for lateral movement (4624/4648).

## 6. False-positive considerations
Some admin tooling and installers use `-enc`. FP indicators: parent is a known
management agent, host is an admin workstation, decoded content is benign
automation. Here the Office parent + external download made TP unambiguous.

## 7. Framework mapping
- **ATT&CK:** T1566 (Phishing) → T1059.001 (PowerShell) → T1105 (Ingress Tool
  Transfer).
- **NIST CSF:** DE.CM (continuous monitoring), RS.AN (analysis),
  RS.MI (mitigation).
