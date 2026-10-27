# AEGENTRA — Multi-Agent Security Automation Platform

An eight-stage, multi-agent pipeline that scans a web application, triages and
analyses the findings, and automatically applies safe, reversible
server-configuration fixes — while routing risky, code-level issues to a human
with an AI-written suggested fix.

AEGENTRA is a **DevSecOps / security-automation** prototype: it combines
vulnerability scanning with automated configuration hardening. It is **not** a
"blue team" detection/monitoring tool, and the agents are coordinated software
services — "agent" here means an independent pipeline stage, not an autonomous
AI making its own decisions.

> **Status:** working prototype, validated on a controlled vulnerable test
> application. See [Current Status](#current-status) for exactly what is
> implemented versus planned.

---

## What it does

1. Scans a target web app with **OWASP ZAP**.
2. Filters and groups the raw alerts into incidents.
3. Analyses each incident using a **rule base** (for exact CWE/MITRE codes) **and
   an LLM** (Google Gemini, for contextual risk reasoning and code-fix
   suggestions), and cross-checks the two.
4. Plans a response, checks it against a safety policy, and **auto-applies safe
   configuration fixes** (e.g. missing security headers) to the live web-server
   config — with a backup kept.
5. Logs everything for audit.

Code-level vulnerabilities (SQL injection, XSS, CSRF) are **never auto-patched**.
They are detected, explained, and logged with a suggested fix for a developer to
review — which is the correct, safe boundary for an automation tool.

---

## Architecture

Eight independent agents communicate through **Apache Kafka** topics. Each agent
reads one topic, does one job, and writes to the next, so any stage can be run or
re-run on its own.

```
                         ┌─────────────────────────────┐
                         │   Target web app (via ZAP)   │
                         └──────────────┬──────────────┘
                                        │ scans
     ┌──────────────────┐   web-detection-alerts
     │ 1. ZAP Scanner   │ ───────────────►┐
     └──────────────────┘                 │
     ┌──────────────────┐   unified-alerts │
     │ 2. Web Monitor   │ ◄───────────────┘  filters noise
     └────────┬─────────┘ ───────────────►┐
     ┌────────▼─────────┐   correlated-incidents
     │ 3. Correlation   │ ◄───────────────┘  groups into incidents
     └────────┬─────────┘ ───────────────►┐
     ┌────────▼─────────┐   llm-analysis    │  rules + Gemini, cross-checked
     │ 4. AI Analysis   │ ◄───────────────┘
     └────────┬─────────┘ ───────────────►┐
     ┌────────▼─────────┐   response-plans  │
     │ 5. Response Plan │ ◄───────────────┘
     └────────┬─────────┘ ───────────────►┐
     ┌────────▼─────────┐   policy-decisions│  safe vs. risky
     │ 6. Policy Valid. │ ◄───────────────┘
     └────────┬─────────┘ ───────────────►┐
     ┌────────▼─────────┐   executed-actions│  patches nginx.conf (safe fixes)
     │ 7. Real Execution│ ◄───────────────┘  + held-for-review (risky)
     └────────┬─────────┘ ───────────────►┐
     ┌────────▼─────────┐   audit-logs      │
     │ 8. Audit         │ ◄───────────────┘
     └──────────────────┘
```

| # | Agent | Reads | Writes | Job |
|---|-------|-------|--------|-----|
| 1 | ZAP Scanner | — (ZAP API) | `web-detection-alerts` | Spider + active scan; publish each alert |
| 2 | Web Monitor | `web-detection-alerts` | `unified-alerts`, `filtered-out-alerts` | Filter noise, forward real findings |
| 3 | Correlation | `unified-alerts` | `correlated-incidents` | Group alerts into incidents (by URL, type, time) |
| 4 | AI Analysis | `correlated-incidents` | `llm-analysis` | Rule + LLM classification, reasoning, code-fix |
| 5 | Response Planning | `llm-analysis` | `response-plans` | Map each incident to actions |
| 6 | Policy Validation | `response-plans` | `policy-decisions` | Approve safe actions, hold risky ones |
| 7 | Real Execution | `policy-decisions` | `executed-actions`, `held-for-review` | Apply safe config patches; route risky to human |
| 8 | Audit | pipeline topics | `audit-logs` | Full audit trail |

---

## The three-source analysis design

The analysis stage draws on **three independent sources**, which may disagree:

| Source | Role | Strength |
|--------|------|----------|
| **ZAP** (scanner) | Raw finding + its own CWE | Direct evidence from the HTTP response |
| **Rule base** (lookup tables) | CWE/MITRE codes + response actions | Fast, deterministic, no hallucination |
| **LLM** (Gemini) | Contextual reasoning, severity-in-context, code-fix | Handles unfamiliar findings; writes real fixes |

The agent records the rule and LLM classifications side by side
(`cwe_rule`/`cwe_llm`, `mitre_rule`/`mitre_llm`) and sets
`classification_agreement` to `agree`, `disagree`, `llm_only`, or `rule_only`.
When they disagree, the rule value is kept as the primary code and the
disagreement is flagged for review. CWE/MITRE codes stay rule-based by design;
the LLM is used for reasoning and remediation, not for overriding the codes.

Every analysis message carries `model_used`: the real model name
(`gemini-3.5-flash`) on a successful LLM call, or a clearly-labelled
`fallback-keyword-*` value if the LLM was unavailable — so LLM output is never
confused with the rule-based fallback.

---

## Tech stack

- **Python 3.12** — all agents
- **Apache Kafka** (+ Zookeeper) — inter-agent messaging; **Kafka UI** on `:8080`
- **OWASP ZAP** 2.17 — vulnerability scanning (daemon on `:8090`)
- **Google Gemini API** (`gemini-3.5-flash`) — LLM analysis (hosted; see note below)
- **Docker** — all services and the test app
- **PostgreSQL / Redis** — provisioned in the stack

> **LLM hosting note:** local inference (Ollama / llama3.2) was tested but proved
> too slow on CPU-only VM hardware, so the pipeline uses the hosted Gemini API.
> An Ollama agent (`ai_analysis_ollama.py`) is included for environments with a
> GPU. Both keep CWE/MITRE rule-based and fall back to keyword matching honestly
> when the model is unavailable.

---

## Project structure

```
Aegentra1/
├── config.yaml                     # targets, topics, patching + infra settings
├── .env.example                    # template for the GEMINI_API_KEY (copy to .env)
├── detection/
│   └── zap_scanner.py              # stage 1: ZAP scan → Kafka
├── agents/
│   ├── base_agent.py               # shared Kafka consumer/producer loop
│   ├── monitoring/                 # stage 2
│   ├── correlation/                # stage 3
│   ├── analysis/
│   │   ├── ai_analysis_agent.py    # stage 4: Gemini + rule cross-validation
│   │   └── ai_analysis_ollama.py   # alternative: local Ollama
│   ├── response/                   # stage 5
│   ├── policy_validation/          # stage 6
│   ├── execution/                  # stage 7: real nginx patching
│   ├── audit/                      # stage 8
│   └── universal/                  # CWE/MITRE maps, policy engine, verification
└── minimal-test-app/
    ├── app.py                      # intentionally vulnerable Flask app
    ├── docker-compose.yml          # flask-app + nginx reverse proxy
    └── nginx.conf                  # the config the execution agent patches
```

---

## How to run

### Prerequisites
- Docker (with `docker-compose`)
- Python 3.12 virtualenv at `aegentra-env`
- A Google Gemini API key (free tier works): https://aistudio.google.com

### 1. Set your API key

Copy the template and add your key (the real `.env` is gitignored — never commit it):

```bash
cp .env.example .env
# edit .env and set: GEMINI_API_KEY=your-key-here
```

### 2. Start infrastructure

```bash
docker start zookeeper && sleep 10
docker start kafka && sleep 30
docker start kafka-ui postgres redis && sleep 10
docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list   # should list topics
```

### 3. Start the test app

```bash
cd minimal-test-app
docker-compose up -d
curl -s http://localhost:8087 | head -3    # should return HTML
cd ..
```

### 4. Start ZAP (first run downloads add-ons; wait for it)

```bash
docker run -d --name zap --network host ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true
# wait until this returns a version:
curl http://127.0.0.1:8090/JSON/core/view/version/
```

### 5. Run the pipeline

```bash
source aegentra-env/bin/activate

python detection/zap_scanner.py                                   # stage 1
timeout 60  python agents/monitoring/web_monitor.py               # stage 2
timeout 90  python agents/correlation/correlation_agent.py        # stage 3
python agents/analysis/ai_analysis_agent.py                       # stage 4 (Gemini)
timeout 120 python agents/response/universal_response_planning_agent.py   # stage 5
timeout 120 python agents/policy_validation/universal_policy_validation_agent.py  # stage 6
timeout 120 python agents/execution/real_execution_agent.py       # stage 7
timeout 60  python agents/audit/audit_agent.py                    # stage 8
```

Inspect results live in **Kafka UI** at http://localhost:8080 (topic
`llm-analysis` shows the analysed incidents).

### 6. Verify a real config patch

```bash
grep add_header minimal-test-app/nginx.conf       # security headers added by the pipeline
```

---

## Current status

**Working today**
- ZAP scanning, Kafka pipeline, filtering, correlation
- Gemini LLM analysis with rule/LLM cross-validation and honest fallback counting
- LLM-generated code-fix suggestions for code-level flaws (developer-review only)
- Real auto-patching of **security headers** to the live nginx config, with backup

**Partial / planned**
- WAF rules, rate limiting, and other config fixes: designed; header patching is
  the fully-working example
- Verification + rollback engine: present (`agents/universal/verification_engine.py`)
  but not yet fully wired into execution
- Correlation grouping: works, but grouping logic can vary run-to-run and is
  being refined

**Known limitations**
- Tested on one controlled vulnerable app, not at production scale
- Rule-based CWE/MITRE tables are hand-written and cover a limited set of vuln
  types; unknown types fall back to a generic label
- The hand-written rule base is the least reliable of the three classification
  sources; where it disagreed with both ZAP and the LLM, it was usually the one
  that was wrong (see Future Work)
- LLM analysis depends on the free Gemini tier, which rate-limits and can be
  temporarily overloaded (handled with retries)

---

## Future work

- **Scanner-primary classification:** make ZAP's evidence-based CWE the primary
  code, use the LLM for enrichment, and use rules for response actions — matching
  how production tools separate "what was found" from "what to do."
- **Three-way cross-validation:** compare scanner, rule, and LLM, and use
  agreement between any two as a confidence signal.
- **Living remediation playbook:** log disagreements and unknown vuln types as
  candidate rule updates, reviewed and applied by a human — turning the rule base
  into a self-improving playbook.
- **Make more safe config fixes real** (WAF, rate limiting) on the proven
  header-patching pattern, and wire in verification + rollback.
- **Retry local/GPU inference** so the LLM stage can run fully offline.

---

## Security note

The `minimal-test-app` is **intentionally vulnerable** and is for local testing
only — never expose it to a network. Only run ZAP scans against systems you own
or are authorised to test. API keys live in `.env` (gitignored), never in code.
