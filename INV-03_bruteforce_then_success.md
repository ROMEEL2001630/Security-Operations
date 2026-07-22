# Investigation Writeup — INV-03

**Alert:** Multiple Failed Logons From Single Source (Brute Force)
**Technique:** T1110 (Brute Force)
**Severity:** Medium → escalates to High if a success follows
**Analyst:** Romeel Bhavsar

---

## 1. Alert summary
47 failed logons (Event ID 4625) from `10.0.5.88` against host `SRV-DC-02`
in 10 minutes, targeting multiple usernames — consistent with password spraying.

## 2. Triage steps
1. **Characterize the pattern.** Many usernames + few attempts each = spraying;
   one username + many attempts = classic brute force. Check `LogonType`
   (3 = network, 10 = RDP).
2. **Did anything succeed?** Pivot to 4624 from the same IP in/after the window:
   `EventID=4624 IpAddress=10.0.5.88`. **One success** found for `svc_backup`.
3. **Assess the account.** `svc_backup` is a service account — should not log in
   interactively from a workstation subnet. Suspicious.
4. **Source context.** Is `10.0.5.88` a known scanner/jump host? Not in the
   asset inventory as either.
5. **Post-auth actions.** Review what `svc_backup` did after logon (process
   creation, share access, new logons outward = lateral movement).

## 3. Evidence collected
- 47× 4625 then 1× 4624 success for `svc_backup` from the same IP.
- Logon type 3 (network); source host not inventoried.
- No approved activity for that service account in the window.

## 4. Verdict
**True Positive — successful password spray → valid account compromise.**

## 5. Escalation & response
- Escalate to Tier 2 / IR.
- **Disable/reset** `svc_backup`; rotate the associated secret.
- Contain source `10.0.5.88`; hunt for lateral movement from `svc_backup`.
- Recommend account-lockout threshold + MFA where possible; add the source IP to
  the watchlist.

## 6. False-positive considerations
Expired cached credentials, misconfigured service accounts, and vuln scanners
cause bursts of 4625. The **follow-on 4624 success** on a service account not
expected to log in interactively is what turns this from noise into an incident.

## 7. Framework mapping
- **ATT&CK:** T1110.003 (Password Spraying) → T1078 (Valid Accounts).
- **NIST CSF:** DE.CM-1, DE.AE-2 (analyze events); **800-53:** AC-7 (unsuccessful
  logon attempts), IA-5 (authenticator management).
