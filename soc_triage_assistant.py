#!/usr/bin/env python3
"""
Agentic AI SOC Triage & Response Assistant
------------------------------------------
Reads a batch of SIEM alerts, enriches their entities, maps each to MITRE
ATT&CK, computes an explainable priority, and drafts an analyst triage note
(optionally with a local/hosted LLM). Every suggested response action is gated
behind analyst approval -- the assistant recommends, the human decides.

This is the "analyst-in-the-loop" design SOCs actually deploy: AI accelerates
summarization and triage; it does not auto-remediate.

Usage:
    python soc_triage_assistant.py sample_alerts.json
    python soc_triage_assistant.py sample_alerts.json --llm ollama --out notes/

Author: Romeel Bhavsar
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None

# Minimal ATT&CK technique -> (name, tactic) lookup for the demo alerts.
ATTACK = {
    "T1059.001": ("PowerShell", "Execution"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1547.001": ("Registry Run Keys", "Persistence"),
    "T1055":     ("Process Injection", "Defense Evasion"),
    "T1110":     ("Brute Force", "Credential Access"),
    "T1078.004": ("Valid Cloud Accounts", "Privilege Escalation"),
    "T1490":     ("Inhibit System Recovery", "Impact"),
    "T1105":     ("Ingress Tool Transfer", "Command and Control"),
    "T1218.010": ("Regsvr32 / Squiblydoo", "Defense Evasion"),
}

SEV_WEIGHT = {"critical": 40, "high": 30, "medium": 15, "low": 5}


# --------------------------------------------------------------------------- #
def load_alerts(path):
    if not os.path.isfile(path):
        sys.exit(f"[!] Alerts file not found: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Invalid JSON: {e}")
    if not isinstance(data, list):
        sys.exit("[!] Expected a JSON list of alert objects.")
    return data


def enrich_ip(ip):
    """AbuseIPDB if a key is present, otherwise a neutral offline stub."""
    key = os.getenv("ABUSEIPDB_API_KEY")
    if requests and key:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers={"Key": key, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": 90},
                             timeout=15)
            d = r.json().get("data", {})
            return {"ip": ip, "abuse_score": d.get("abuseConfidenceScore"),
                    "country": d.get("countryCode"), "source": "abuseipdb"}
        except Exception as e:
            return {"ip": ip, "error": str(e), "source": "abuseipdb"}
    return {"ip": ip, "abuse_score": None, "source": "offline",
            "note": "set ABUSEIPDB_API_KEY to enable live enrichment"}


def priority(alert, enrichment):
    """Explainable score: severity + asset criticality + tactic + TI signal."""
    score, reasons = 0, []
    sev = str(alert.get("severity", "medium")).lower()
    score += SEV_WEIGHT.get(sev, 15); reasons.append(f"severity={sev}")

    if alert.get("asset_criticality", "").lower() in ("high", "crown-jewel"):
        score += 20; reasons.append("high-criticality asset")

    tech = alert.get("technique", "")
    tactic = ATTACK.get(tech, ("", ""))[1]
    if tactic in ("Impact", "Credential Access", "Privilege Escalation"):
        score += 15; reasons.append(f"high-impact tactic ({tactic})")

    for e in enrichment:
        s = e.get("abuse_score")
        if isinstance(s, int) and s >= 50:
            score += 15; reasons.append(f"malicious IP {e['ip']} (abuse {s})")

    score = min(score, 100)
    band = ("P1 - Critical" if score >= 70 else
            "P2 - High" if score >= 45 else
            "P3 - Medium" if score >= 25 else "P4 - Low")
    return score, band, reasons


SUGGESTED = {
    "T1003.001": ["Isolate host (EDR)", "Reset exposed credentials",
                  "Hunt for lateral movement (4624/4648)"],
    "T1078.004": ["Rotate root/user secret", "Revoke attacker access keys",
                  "Enforce MFA; confirm CloudTrail not disabled"],
    "T1490":     ["Isolate host immediately", "Check for encryption in progress",
                  "Engage IR / ransomware playbook"],
    "T1110":     ["Confirm any 4624 success from source", "Disable/reset account",
                  "Block source IP; recommend lockout + MFA"],
    "T1059.001": ["Decode payload (CyberChef)", "Review process tree",
                  "Block C2 IOCs; isolate if TP"],
}
DEFAULT_ACTIONS = ["Validate against baseline", "Enrich remaining IOCs",
                   "Escalate to Tier 2 if confirmed"]


def template_note(alert, tactic, tech_name, band, score, reasons, enrichment):
    """Deterministic triage note used when no LLM is selected."""
    ioc_lines = ", ".join(a.get("ip", "") for a in enrichment) or "none"
    return (
        f"Alert {alert.get('id')} ({alert.get('rule')}) on host "
        f"{alert.get('host')} / user {alert.get('user')} maps to {alert.get('technique')} "
        f"- {tech_name} ({tactic}). Priority {band} (score {score}: "
        f"{'; '.join(reasons)}). Observed IPs: {ioc_lines}. Recommend an analyst "
        f"confirm the verdict before any response action."
    )


def llm_note(alert, tactic, tech_name, band, reasons, enrichment, mode):
    prompt = (
        "You are a SOC Tier-1 analyst assistant. Write a concise 3-4 sentence "
        "triage note for this alert: what fired, the ATT&CK technique/tactic, the "
        "priority and why, and the single most important next check. Do not invent "
        "indicators. End by reminding that response actions need analyst approval.\n\n"
        + json.dumps({"alert": alert, "tactic": tactic, "technique": tech_name,
                      "priority": band, "reasons": reasons,
                      "enrichment": enrichment}, indent=2))
    if requests is None:
        return "(LLM skipped: requests not installed)"
    try:
        if mode == "ollama":
            r = requests.post("http://localhost:11434/api/generate",
                              json={"model": os.getenv("OLLAMA_MODEL", "llama3"),
                                    "prompt": prompt, "stream": False}, timeout=120)
            return r.json().get("response", "").strip()
        if mode == "openai":
            key = os.getenv("OPENAI_API_KEY")
            if not key:
                return "(LLM skipped: OPENAI_API_KEY not set)"
            r = requests.post("https://api.openai.com/v1/chat/completions",
                              headers={"Authorization": f"Bearer {key}"},
                              json={"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                                    "messages": [{"role": "user", "content": prompt}]},
                              timeout=120)
            return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"(LLM error: {e})"
    return "(unknown LLM mode)"


def process(alert, mode):
    entities = alert.get("entities", {})
    enrichment = [enrich_ip(ip) for ip in entities.get("ips", [])]
    score, band, reasons = priority(alert, enrichment)
    tech = alert.get("technique", "")
    tech_name, tactic = ATTACK.get(tech, ("Unknown", "Unknown"))
    if mode:
        note = llm_note(alert, tactic, tech_name, band, reasons, enrichment, mode)
    else:
        note = template_note(alert, tactic, tech_name, band, score, reasons, enrichment)
    actions = SUGGESTED.get(tech, DEFAULT_ACTIONS)
    return {"alert": alert, "score": score, "band": band, "reasons": reasons,
            "tactic": tactic, "tech_name": tech_name, "enrichment": enrichment,
            "note": note, "actions": actions}


def render(result):
    a = result["alert"]
    L = [f"## {a.get('id')} - {a.get('rule')}  [{result['band']}]",
         f"- Host: {a.get('host')} | User: {a.get('user')} | Time: {a.get('timestamp')}",
         f"- ATT&CK: {a.get('technique')} - {result['tech_name']} ({result['tactic']})",
         f"- Priority score: {result['score']}/100 ({'; '.join(result['reasons'])})",
         f"\n**Triage note (AI-assisted):** {result['note']}",
         "\n**Suggested actions — REQUIRE ANALYST APPROVAL:**"]
    L += [f"  - [ ] {act}" for act in result["actions"]]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Agentic AI SOC triage assistant")
    ap.add_argument("alerts", help="Path to alerts JSON (list of objects)")
    ap.add_argument("--llm", choices=["ollama", "openai"], help="LLM for notes")
    ap.add_argument("--out", help="Directory to write per-alert notes")
    args = ap.parse_args()

    alerts = load_alerts(args.alerts)
    results = [process(a, args.llm) for a in alerts]
    results.sort(key=lambda r: r["score"], reverse=True)

    print(f"# SOC Triage Queue  ({len(results)} alerts, sorted by priority)")
    print(f"_Generated {datetime.now(timezone.utc).isoformat()} — "
          f"analyst-in-the-loop; no automated response taken._\n")
    print("| Priority | Score | Alert | Technique | Host |")
    print("|----------|-------|-------|-----------|------|")
    for r in results:
        print(f"| {r['band']} | {r['score']} | {r['alert'].get('id')} | "
              f"{r['alert'].get('technique')} | {r['alert'].get('host')} |")
    print()
    for r in results:
        print(render(r)); print()

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for r in results:
            fn = os.path.join(args.out, f"{r['alert'].get('id','alert')}.md")
            with open(fn, "w", encoding="utf-8") as fh:
                fh.write(render(r))
        print(f"[+] Wrote {len(results)} notes to {args.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
