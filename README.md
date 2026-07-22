# IOC Enrichment CLI (SOAR-ready)

Auto-detects an indicator's type (IP / domain / URL / hash), queries free
threat-intel sources, and returns an aggregated **risk verdict** as JSON or
Markdown. Built to slot into a **Shuffle** (free, open-source SOAR) workflow:
feed it one IOC, branch on the JSON it returns.

This covers the "security automation with Python" keyword cleanly and shows you
understand how enrichment fits into an automated SOC pipeline.

## Sources (free tiers)
- **AbuseIPDB** — IP reputation (`ABUSEIPDB_API_KEY`)
- **VirusTotal** — IP / domain / hash / URL (`VT_API_KEY`)
- **AlienVault OTX** — pulses across all types (`OTX_API_KEY`)

Runs offline without keys (returns structure + notes) so it's safe to demo.

## Usage
```bash
# Single IOC -> JSON (Shuffle-friendly)
python ioc_enrich.py 203.0.113.77

# Batch a file -> Markdown table
python ioc_enrich.py --file iocs.txt

# Explicit JSON to a file
python ioc_enrich.py evil.example.com --json --out result.json
```

## Aggregated verdict
The tool takes the strongest signal across sources (AbuseIPDB confidence, VT
malicious count, OTX pulse count) → 0-100 → `clean/unknown | suspicious |
malicious`. Logic is explainable and in code.

## Shuffle integration (free SOAR)
1. Install Shuffle (Docker) — https://shuffler.io.
2. Add a trigger (webhook or SIEM alert) that provides an IOC.
3. Run this script in a "Shell"/"Python" node with the IOC as `argv`.
4. Branch on `.verdict`: `malicious` → create ticket / block; else → close.

## Skills demonstrated
Security automation (Python) · threat-intel enrichment · IOC typing &
normalization · SOAR workflow design · API integration.

## Resume line (truthful)
> Built a Python IOC-enrichment tool that auto-detects indicator types and
> aggregates AbuseIPDB, VirusTotal, and OTX reputation into a single risk
> verdict, designed to plug into a Shuffle SOAR workflow.

*Author: Romeel Bhavsar*
