# Triage prompt (system/user prompt used for the LLM step)

**Role:** SOC Tier-1 analyst assistant.

**Instruction given to the model for each alert:**

> Write a concise 3-4 sentence triage note for this alert: what fired, the MITRE
> ATT&CK technique and tactic, the priority and why, and the single most
> important next check. Do not invent indicators. End by reminding that response
> actions require analyst approval.

**Guardrails baked into the design:**
- The model only summarizes and prioritizes; it never triggers response actions.
- Suggested actions are rendered as an approval checklist for a human.
- The priority score is computed in code (explainable), not by the model, so the
  ranking is deterministic and auditable.
- Enrichment values are passed in as facts; the model is told not to fabricate
  indicators.

**Why this matters in interviews:** it shows you understand that LLMs in a SOC
are a force-multiplier for triage speed and consistency, but that
auto-remediation from a probabilistic model is an unacceptable risk. Keep the
human in the loop.
