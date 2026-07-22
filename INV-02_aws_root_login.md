# Investigation Writeup — INV-02

**Alert:** AWS Root Account Console Login
**Technique:** T1078.004 (Valid Accounts: Cloud Accounts)
**Severity:** High
**Analyst:** Romeel Bhavsar

---

## 1. Alert summary
CloudTrail `ConsoleLogin` with `userIdentity.type = Root`. Root is meant for
break-glass only, so any interactive root login is investigated immediately.
Source IP `203.0.113.77`, `MFAUsed = No`.

## 2. Triage steps
1. **MFA check.** `additionalEventData.MFAUsed` = `No` → immediate red flag.
   Root without MFA violates baseline policy.
2. **Geolocate & reputation the source IP.** AbuseIPDB / MaxMind. Compare to
   known admin egress IPs. `203.0.113.77` geolocates outside expected region.
3. **Change-ticket correlation.** Is there an approved break-glass request for
   this window? None found.
4. **Blast-radius review.** Pull all CloudTrail events for this session's
   `accessKeyId` / session: look for `CreateUser`, `CreateAccessKey`,
   `AttachUserPolicy`, `PutUserPolicy`, `DeleteTrail`, `StopLogging`.
5. **Result correlation.** `responseElements.ConsoleLogin = Success`.

## 3. Evidence collected
- Root login success, no MFA, foreign IP, no change ticket.
- Follow-on: `CreateAccessKey` for root within 4 minutes → attacker
  establishing persistence.

## 4. Verdict
**True Positive — account compromise.** Unauthorized root access with
persistence actions.

## 5. Escalation & response
- Escalate to IR and the cloud/account owner immediately.
- **Rotate** root password; **delete** the attacker-created access key.
- Enforce/enable **MFA on root**; review IAM for other unauthorized keys/users.
- Confirm CloudTrail was not stopped (`StopLogging`/`DeleteTrail`).
- Preserve CloudTrail events (export the relevant window) for the case record.

## 6. False-positive considerations
Legitimate pre-approved break-glass usage is the only benign path. Confirm via
change ticket **and** MFA. Here both were absent and persistence was created —
clear TP.

## 7. Framework mapping
- **ATT&CK:** T1078.004 (Valid Cloud Accounts), T1098 (Account Manipulation).
- **NIST SP 800-53:** AC-2 (account management), AC-6 (least privilege),
  AU-6 (audit review), IA-2 (MFA).
