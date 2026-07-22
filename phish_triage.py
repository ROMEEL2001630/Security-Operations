#!/usr/bin/env python3
"""
Phishing Triage Analyzer
------------------------
Parses a raw .eml file, extracts indicators of compromise (IOCs), runs
authentication and heuristic checks, optionally enriches IOCs against free
threat-intel APIs, and (optionally) generates an analyst summary with a local
or hosted LLM. Produces a Markdown report and a JSON IOC bundle.

Design goals for a SOC context:
  * Analyst-in-the-loop: the tool recommends a verdict, it does not auto-action.
  * Runs fully offline (no API keys) for safe practice; enrichment is optional.
  * Defangs URLs/IPs in output so reports are safe to paste into tickets.

Usage:
    python phish_triage.py sample_emails/sample_phish.eml
    python phish_triage.py msg.eml --enrich --llm ollama --out report.md

Author: Romeel Bhavsar
"""

import argparse
import email
import email.policy
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# requests is optional: only needed for --enrich / hosted --llm.
try:
    import requests
except ImportError:
    requests = None

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE_IP_RE = re.compile(r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")


# --------------------------------------------------------------------------- #
# Parsing & extraction
# --------------------------------------------------------------------------- #
def load_email(path):
    """Read a .eml file into an EmailMessage, or exit with a clear error."""
    if not os.path.isfile(path):
        sys.exit(f"[!] File not found: {path}")
    with open(path, "rb") as fh:
        return email.message_from_binary_file(fh, policy=email.policy.default)


def get_bodies(msg):
    """Return (text_body, html_body) as strings, handling multipart safely."""
    text_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain":
                text_body += str(payload)
            elif ctype == "text/html":
                html_body += str(payload)
    else:
        try:
            text_body = str(msg.get_content())
        except Exception:
            text_body = ""
    return text_body, html_body


def extract_attachments(msg):
    """Return metadata + SHA-256 for each attachment (never executes them)."""
    out = []
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        if "attachment" not in disp:
            continue
        name = part.get_filename() or "(unnamed)"
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        out.append({
            "filename": name,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest() if data else None,
            "content_type": part.get_content_type(),
        })
    return out


def extract_iocs(text_body, html_body, msg):
    """Pull URLs, external IPs, and sender domains out of the message."""
    combined = f"{text_body}\n{html_body}"
    urls = sorted(set(URL_RE.findall(combined)))

    # Received headers usually carry the real originating IPs.
    received = " ".join(msg.get_all("Received", []))
    ips = sorted({ip for ip in IPV4_RE.findall(received)
                  if not PRIVATE_IP_RE.match(ip)})

    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    from_dom = domain_of(from_addr)
    url_domains = sorted({urldomain(u) for u in urls if urldomain(u)})
    return {
        "urls": urls,
        "url_domains": url_domains,
        "external_ips": ips,
        "from": from_addr,
        "from_domain": from_dom,
        "reply_to": reply_to,
    }


def domain_of(addr):
    m = re.search(r"@([A-Za-z0-9.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def urldomain(url):
    m = re.match(r"https?://([^/:]+)", url or "", re.IGNORECASE)
    return m.group(1).lower() if m else ""


# --------------------------------------------------------------------------- #
# Authentication & heuristic scoring
# --------------------------------------------------------------------------- #
def check_auth(msg, iocs):
    """Read SPF/DKIM/DMARC results and look for sender-spoofing signals."""
    auth = str(msg.get("Authentication-Results", "")).lower()
    findings = {
        "spf": "pass" if "spf=pass" in auth else ("fail" if "spf=fail" in auth
                else ("softfail" if "spf=softfail" in auth else "unknown")),
        "dkim": "pass" if "dkim=pass" in auth else ("fail" if "dkim=fail" in auth
                 else "unknown"),
        "dmarc": "pass" if "dmarc=pass" in auth else ("fail" if "dmarc=fail" in auth
                  else "unknown"),
    }
    reply_dom = domain_of(iocs["reply_to"])
    findings["replyto_mismatch"] = bool(
        reply_dom and iocs["from_domain"] and reply_dom != iocs["from_domain"])
    return findings


def heuristic_score(iocs, auth, attachments, text_body, html_body):
    """Simple explainable risk score. Each hit adds points + a reason."""
    score, reasons = 0, []

    if auth["spf"] in ("fail", "softfail"):
        score += 20; reasons.append(f"SPF {auth['spf']}")
    if auth["dkim"] == "fail":
        score += 15; reasons.append("DKIM fail")
    if auth["dmarc"] == "fail":
        score += 20; reasons.append("DMARC fail")
    if auth["replyto_mismatch"]:
        score += 15; reasons.append("Reply-To domain differs from From domain")

    # Display-name / link mismatch and lure language.
    body = f"{text_body} {html_body}".lower()
    lures = ["verify your account", "password will expire", "unusual sign-in",
             "confirm your", "urgent", "invoice attached", "gift card",
             "update your payment", "account suspended"]
    hit = [l for l in lures if l in body]
    if hit:
        score += min(15, 5 * len(hit)); reasons.append(f"Lure phrases: {', '.join(hit[:3])}")

    risky_ext = (".exe", ".scr", ".js", ".vbs", ".iso", ".img", ".htm",
                 ".html", ".lnk", ".zip", ".rar", ".7z", ".docm", ".xlsm")
    for a in attachments:
        if a["filename"].lower().endswith(risky_ext):
            score += 20; reasons.append(f"Risky attachment: {a['filename']}")

    # Raw-IP or many distinct link domains in the body.
    if any(IPV4_RE.search(u) for u in iocs["urls"]):
        score += 10; reasons.append("URL uses a raw IP address")
    if len(iocs["url_domains"]) >= 4:
        score += 5; reasons.append("Many distinct link domains")

    score = min(score, 100)
    verdict = ("Malicious / High" if score >= 60 else
               "Suspicious / Medium" if score >= 30 else
               "Likely benign / Low")
    return score, verdict, reasons


# --------------------------------------------------------------------------- #
# Optional enrichment (free APIs, keys via environment variables)
# --------------------------------------------------------------------------- #
def enrich(iocs):
    """Best-effort enrichment. Silently skips any source without a key."""
    results = {"abuseipdb": [], "virustotal": [], "notes": []}
    if requests is None:
        results["notes"].append("requests not installed - enrichment skipped")
        return results

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    vt_key = os.getenv("VT_API_KEY")

    if abuse_key:
        for ip in iocs["external_ips"][:5]:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
                d = r.json().get("data", {})
                results["abuseipdb"].append({
                    "ip": ip,
                    "abuseConfidenceScore": d.get("abuseConfidenceScore"),
                    "countryCode": d.get("countryCode"),
                    "isp": d.get("isp"),
                })
            except Exception as e:
                results["notes"].append(f"AbuseIPDB error for {ip}: {e}")
    else:
        results["notes"].append("ABUSEIPDB_API_KEY not set - IP enrichment skipped")

    if vt_key:
        for dom in iocs["url_domains"][:5]:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{dom}",
                    headers={"x-apikey": vt_key}, timeout=15)
                stats = (r.json().get("data", {}).get("attributes", {})
                         .get("last_analysis_stats", {}))
                results["virustotal"].append({
                    "domain": dom,
                    "malicious": stats.get("malicious"),
                    "suspicious": stats.get("suspicious"),
                })
            except Exception as e:
                results["notes"].append(f"VirusTotal error for {dom}: {e}")
    else:
        results["notes"].append("VT_API_KEY not set - domain enrichment skipped")
    return results


# --------------------------------------------------------------------------- #
# Optional LLM analyst summary
# --------------------------------------------------------------------------- #
def llm_summary(context, mode):
    """Generate a short analyst summary. mode: 'ollama' (local) or 'openai'."""
    prompt = (
        "You are a SOC Tier-1 analyst. Given this phishing triage data, write a "
        "4-5 sentence summary: what the email is, the strongest malicious "
        "indicators, a recommended verdict, and the next action. Be concise and "
        "do NOT invent indicators.\n\n"
        f"{json.dumps(context, indent=2)}"
    )
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
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=120)
            return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"(LLM error: {e})"
    return "(LLM mode not recognized)"


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def defang(s):
    return (s or "").replace("http", "hxxp").replace(".", "[.]")


def build_report(meta, iocs, auth, attachments, score, verdict, reasons,
                 enrichment, summary):
    L = []
    L.append(f"# Phishing Triage Report\n")
    L.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    L.append(f"- **Subject:** {meta['subject']}")
    L.append(f"- **From:** {meta['from']}")
    L.append(f"- **Reply-To:** {iocs['reply_to'] or '(none)'}")
    L.append(f"- **Date:** {meta['date']}\n")
    L.append(f"## Verdict: {verdict}  (risk score {score}/100)")
    if summary:
        L.append(f"\n**Analyst summary (LLM-assisted):** {summary}\n")
    L.append("## Why (heuristic reasons)")
    L += [f"- {r}" for r in reasons] or ["- No strong indicators triggered"]
    L.append("\n## Authentication")
    L.append(f"- SPF: {auth['spf']} | DKIM: {auth['dkim']} | DMARC: {auth['dmarc']}")
    L.append(f"- Reply-To mismatch: {auth['replyto_mismatch']}")
    L.append("\n## IOCs (defanged)")
    L.append("**URLs:**")
    L += [f"- {defang(u)}" for u in iocs["urls"]] or ["- (none)"]
    L.append("**External IPs (from Received):**")
    L += [f"- {defang(ip)}" for ip in iocs["external_ips"]] or ["- (none)"]
    L.append("**Attachments:**")
    L += [f"- {a['filename']} | {a['size_bytes']} B | SHA256 {a['sha256']}"
          for a in attachments] or ["- (none)"]
    if enrichment and (enrichment["abuseipdb"] or enrichment["virustotal"]):
        L.append("\n## Enrichment")
        for e in enrichment["abuseipdb"]:
            L.append(f"- AbuseIPDB {e['ip']}: confidence {e['abuseConfidenceScore']} "
                     f"({e['countryCode']}, {e['isp']})")
        for e in enrichment["virustotal"]:
            L.append(f"- VT {e['domain']}: malicious {e['malicious']}, "
                     f"suspicious {e['suspicious']}")
    L.append("\n## Recommended next action")
    L.append("Analyst-in-the-loop: confirm verdict, then (if malicious) block "
             "sender/domain/IP, purge from mailboxes, and check for other "
             "recipients and any clicks.")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Phishing triage analyzer")
    ap.add_argument("eml", help="Path to the .eml file")
    ap.add_argument("--enrich", action="store_true", help="Query free TI APIs")
    ap.add_argument("--llm", choices=["ollama", "openai"], help="LLM summary")
    ap.add_argument("--out", help="Write Markdown report to this path")
    ap.add_argument("--json", help="Write IOC bundle JSON to this path")
    args = ap.parse_args()

    msg = load_email(args.eml)
    text_body, html_body = get_bodies(msg)
    attachments = extract_attachments(msg)
    iocs = extract_iocs(text_body, html_body, msg)
    auth = check_auth(msg, iocs)
    score, verdict, reasons = heuristic_score(
        iocs, auth, attachments, text_body, html_body)

    enrichment = enrich(iocs) if args.enrich else None
    context = {"subject": str(msg.get("Subject", "")), "verdict": verdict,
               "score": score, "reasons": reasons, "auth": auth, "iocs": iocs}
    summary = llm_summary(context, args.llm) if args.llm else ""

    meta = {"subject": str(msg.get("Subject", "")),
            "from": iocs["from"], "date": str(msg.get("Date", ""))}
    report = build_report(meta, iocs, auth, attachments, score, verdict,
                          reasons, enrichment, summary)

    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"\n[+] Report written to {args.out}", file=sys.stderr)
    if args.json:
        bundle = {"meta": meta, "iocs": iocs, "auth": auth,
                  "attachments": attachments, "score": score,
                  "verdict": verdict, "reasons": reasons}
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2)
        print(f"[+] IOC bundle written to {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
