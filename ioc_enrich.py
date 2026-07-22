#!/usr/bin/env python3
"""
IOC Enrichment CLI (SOAR-ready)
-------------------------------
Takes an indicator (IPv4, domain, URL, MD5/SHA1/SHA256) or a file of indicators,
auto-detects the type, queries free threat-intel sources, and returns an
aggregated risk verdict as JSON or Markdown.

Designed to be dropped into a SOAR workflow (e.g., Shuffle): pass one IOC, get
structured JSON on stdout that the next node can branch on.

Sources (all have free tiers; keys via env vars):
  * AbuseIPDB   (IPs)                ABUSEIPDB_API_KEY
  * VirusTotal  (IP/domain/hash)     VT_API_KEY
  * AlienVault OTX (all types)       OTX_API_KEY

Runs offline without keys (returns structure + notes) so it's safe to demo.

    python ioc_enrich.py 8.8.8.8
    python ioc_enrich.py evil.example.com --json
    python ioc_enrich.py --file iocs.txt --out results.json

Author: Romeel Bhavsar
"""

import argparse
import ipaddress
import json
import os
import re
import sys

try:
    import requests
except ImportError:
    requests = None

HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


def detect_type(ioc):
    ioc = ioc.strip().strip('"').strip("'")
    if ioc.lower().startswith(("http://", "https://")):
        return "url", ioc
    try:
        ipaddress.ip_address(ioc)
        return "ip", ioc
    except ValueError:
        pass
    for name, rx in HASH_RE.items():
        if rx.match(ioc):
            return "hash", ioc
    if DOMAIN_RE.match(ioc):
        return "domain", ioc.lower()
    return "unknown", ioc


# --------------------------------------------------------------------------- #
# Source queries (best-effort; each degrades gracefully)
# --------------------------------------------------------------------------- #
def q_abuseipdb(ioc):
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not (requests and key):
        return {"source": "abuseipdb", "skipped": "no key or requests"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"ipAddress": ioc, "maxAgeInDays": 90}, timeout=15)
        d = r.json().get("data", {})
        return {"source": "abuseipdb",
                "abuseConfidenceScore": d.get("abuseConfidenceScore"),
                "totalReports": d.get("totalReports"),
                "countryCode": d.get("countryCode"), "isp": d.get("isp")}
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e)}


def q_virustotal(ioc, itype):
    key = os.getenv("VT_API_KEY")
    if not (requests and key):
        return {"source": "virustotal", "skipped": "no key or requests"}
    path = {"ip": "ip_addresses", "domain": "domains",
            "hash": "files", "url": "urls"}.get(itype)
    if not path:
        return {"source": "virustotal", "skipped": f"type {itype} unsupported"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}/{ioc}",
                         headers={"x-apikey": key}, timeout=15)
        stats = (r.json().get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        return {"source": "virustotal", "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless")}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


def q_otx(ioc, itype):
    key = os.getenv("OTX_API_KEY")
    if not (requests and key):
        return {"source": "otx", "skipped": "no key or requests"}
    section = {"ip": "IPv4", "domain": "domain",
               "hash": "file", "url": "url"}.get(itype)
    if not section:
        return {"source": "otx", "skipped": f"type {itype} unsupported"}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general",
            headers={"X-OTX-API-KEY": key}, timeout=15)
        d = r.json()
        return {"source": "otx",
                "pulse_count": d.get("pulse_info", {}).get("count", 0)}
    except Exception as e:
        return {"source": "otx", "error": str(e)}


# --------------------------------------------------------------------------- #
def aggregate_verdict(results):
    """Combine source signals into a 0-100 score + verdict."""
    score, signals = 0, []
    for r in results:
        if r["source"] == "abuseipdb" and isinstance(r.get("abuseConfidenceScore"), int):
            score = max(score, r["abuseConfidenceScore"])
            signals.append(f"AbuseIPDB {r['abuseConfidenceScore']}")
        if r["source"] == "virustotal" and isinstance(r.get("malicious"), int):
            vt = min(100, r["malicious"] * 10)
            score = max(score, vt)
            signals.append(f"VT malicious {r['malicious']}")
        if r["source"] == "otx" and isinstance(r.get("pulse_count"), int) and r["pulse_count"] > 0:
            score = max(score, min(100, 40 + r["pulse_count"]))
            signals.append(f"OTX pulses {r['pulse_count']}")
    verdict = ("malicious" if score >= 60 else
               "suspicious" if score >= 25 else
               "clean/unknown")
    return {"risk_score": score, "verdict": verdict, "signals": signals}


def enrich_one(ioc):
    itype, norm = detect_type(ioc)
    results = []
    if itype == "ip":
        results.append(q_abuseipdb(norm))
    results.append(q_virustotal(norm, itype))
    results.append(q_otx(norm, itype))
    out = {"ioc": norm, "type": itype, "sources": results}
    out.update(aggregate_verdict(results))
    return out


def read_iocs(path):
    if not os.path.isfile(path):
        sys.exit(f"[!] File not found: {path}")
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def to_markdown(items):
    L = ["# IOC Enrichment Results\n",
         "| IOC | Type | Verdict | Score | Signals |",
         "|-----|------|---------|-------|---------|"]
    for it in items:
        sig = ", ".join(it["signals"]) or "(no live sources — set API keys)"
        L.append(f"| {it['ioc']} | {it['type']} | {it['verdict']} | "
                 f"{it['risk_score']} | {sig} |")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="IOC enrichment (SOAR-ready)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("ioc", nargs="?", help="A single IOC")
    g.add_argument("--file", help="File with one IOC per line")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--out", help="Write output to a file")
    args = ap.parse_args()

    iocs = read_iocs(args.file) if args.file else [args.ioc]
    items = [enrich_one(i) for i in iocs]

    # Single-IOC JSON is the Shuffle-friendly default.
    if args.json or (args.ioc and not args.file):
        payload = items[0] if (args.ioc and not args.file) else items
        text = json.dumps(payload, indent=2)
    else:
        text = to_markdown(items)

    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[+] Written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
