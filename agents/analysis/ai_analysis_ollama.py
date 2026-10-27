#!/usr/bin/env python3
"""
AEGENTRA AI Analysis Agent — Ollama (llama3.2)
Drop-in replacement for ai_analysis_agent.py.
Same Kafka topics: reads correlated-incidents, writes llm-analysis.
Falls back to keyword matching when Ollama is unreachable or returns invalid JSON.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
import json
import logging
import time
import yaml
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Ollama connection settings
# ─────────────────────────────────────────────────────────────────────────────
OLLAMA_URL   = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2"

# ─────────────────────────────────────────────────────────────────────────────
# Vocabulary constrained to what action_mapper.py understands exactly.
# CWE and MITRE come from rule-based tables below — never from the model.
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_THREAT_TYPES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Cross-Site Request Forgery (CSRF)",
    "Authentication Bypass",
    "Arbitrary File Upload",
    "Information Disclosure",
    "Missing Security Headers",
    "Directory Traversal",
    "Command Injection",
    "XML External Entity (XXE)",
    "Server-Side Request Forgery (SSRF)",
    "Security Vulnerability",
]

ALLOWED_MITRE = {
    "T1190": "Initial Access",
    "T1059": "Execution",
    "T1078": "Defense Evasion",
    "T1083": "Discovery",
    "T1110": "Credential Access",
    "T1133": "Initial Access",
    "T1189": "Execution",
    "T1566": "Initial Access",
    "T1210": "Lateral Movement",
    "T1505": "Persistence",
    "T1090": "Command and Control",
}

CODE_FIX_THREAT_TYPES = {
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Cross-Site Request Forgery (CSRF)",
}

THREAT_ACTIONS = {
    "SQL Injection":                      ["use_prepared_statements", "add_input_validation", "add_waf_rule"],
    "Cross-Site Scripting (XSS)":         ["add_output_encoding", "add_content_security_policy", "sanitize_user_inputs"],
    "Cross-Site Request Forgery (CSRF)":  ["implement_csrf_tokens", "validate_origin", "add_samesite_cookies"],
    "Authentication Bypass":              ["strengthen_authentication", "add_mfa", "implement_rate_limiting"],
    "Arbitrary File Upload":              ["validate_file_types", "scan_uploads", "restrict_execution"],
    "Information Disclosure":             ["remove_verbose_errors", "sanitize_responses", "add_security_headers"],
    "Missing Security Headers":           ["add_security_headers", "configure_web_server", "update_response_headers"],
    "Directory Traversal":                ["validate_file_paths", "implement_whitelist", "restrict_file_access"],
    "Command Injection":                  ["sanitize_command_inputs", "use_safe_apis", "implement_input_validation"],
    "XML External Entity (XXE)":          ["disable_external_entities", "use_safe_xml_parsers", "validate_xml_inputs"],
    "Server-Side Request Forgery (SSRF)": ["validate_urls", "implement_whitelist", "restrict_outbound_requests"],
    "Security Vulnerability":             ["alert_security_team", "enable_enhanced_monitoring"],
}

# Rule-based CWE lookup — the model is never asked for a CWE
THREAT_CWE = {
    "SQL Injection":                      "89",
    "Cross-Site Scripting (XSS)":         "79",
    "Cross-Site Request Forgery (CSRF)":  "352",
    "Authentication Bypass":              "287",
    "Arbitrary File Upload":              "434",
    "Information Disclosure":             "200",
    "Missing Security Headers":           "693",
    "Directory Traversal":                "22",
    "Command Injection":                  "77",
    "XML External Entity (XXE)":          "611",
    "Server-Side Request Forgery (SSRF)": "918",
    "Security Vulnerability":             "0",
}

# Rule-based MITRE lookup — the model is never asked for a MITRE technique
THREAT_MITRE = {
    "SQL Injection":                      ("T1190", "Initial Access"),
    "Cross-Site Scripting (XSS)":         ("T1189", "Execution"),
    "Cross-Site Request Forgery (CSRF)":  ("T1566", "Initial Access"),
    "Authentication Bypass":              ("T1078", "Defense Evasion"),
    "Arbitrary File Upload":              ("T1505", "Persistence"),
    "Information Disclosure":             ("T1083", "Discovery"),
    "Missing Security Headers":           ("T1190", "Initial Access"),
    "Directory Traversal":                ("T1083", "Discovery"),
    "Command Injection":                  ("T1059", "Execution"),
    "XML External Entity (XXE)":          ("T1190", "Initial Access"),
    "Server-Side Request Forgery (SSRF)": ("T1090", "Command and Control"),
    "Security Vulnerability":             ("T1190", "Initial Access"),
}

# Default severity/confidence per threat type (used when Ollama is unavailable)
THREAT_SEVERITY_DEFAULTS = {
    "SQL Injection":                      (9, 0.95),
    "Cross-Site Scripting (XSS)":         (8, 0.90),
    "Cross-Site Request Forgery (CSRF)":  (7, 0.85),
    "Authentication Bypass":              (9, 0.90),
    "Arbitrary File Upload":              (8, 0.85),
    "Information Disclosure":             (5, 0.80),
    "Missing Security Headers":           (4, 0.75),
    "Directory Traversal":                (7, 0.85),
    "Command Injection":                  (9, 0.95),
    "XML External Entity (XXE)":          (8, 0.90),
    "Server-Side Request Forgery (SSRF)": (8, 0.90),
    "Security Vulnerability":             (6, 0.70),
}


class OllamaAnalysisAgent(BaseAgent):
    """
    AEGENTRA analysis agent backed by local Ollama (llama3.2).

    What the model does:
      - Assesses severity (1-10) in context of the specific evidence
      - Assigns confidence (0.0-1.0)
      - Writes a plain-language reasoning paragraph
      - Suggests a code fix for SQLi/XSS/CSRF (labeled: developer review, never auto-applied)

    What the model does NOT do:
      - Classify the threat type (keyword lookup handles this)
      - Provide CWE IDs (THREAT_CWE rule table)
      - Provide MITRE technique/tactic (THREAT_MITRE rule table)
    """

    def __init__(self):
        super().__init__(
            agent_name="OllamaAnalysisAgent-llama3.2-v1",
            input_topic="correlated-incidents",
            output_topic="llm-analysis",
            consumer_kwargs={"max_poll_interval_ms": 1800000},  # 30 min — LLM calls can be slow
        )

        self.model_name = OLLAMA_MODEL
        self.ollama_url = OLLAMA_URL

        # OLLAMA_TEST_LIMIT: stop after this many incidents (0 = unlimited)
        try:
            self.test_limit = int(os.environ.get("OLLAMA_TEST_LIMIT", "5"))
        except ValueError:
            self.test_limit = 5

        self.llm_success_count = 0
        self.fallback_count    = 0
        self.processed_count   = 0
        self.llm_call_times: list = []

        config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml")
        with open(config_path) as f:
            config = yaml.safe_load(f)
        self.code_fix_log = config.get("monitoring", {}).get(
            "code_fix_log", "/tmp/aegentra_code_fixes.log"
        )

        limit_str = "unlimited" if self.test_limit == 0 else str(self.test_limit)
        logger.info("✅ Ollama Analysis Agent initialised")
        logger.info(f"   Model        : {self.model_name} at {self.ollama_url}")
        logger.info(f"   Test limit   : {limit_str} incidents (OLLAMA_TEST_LIMIT env var)")
        logger.info("   Timeout      : none (waits as long as the model needs)")
        logger.info(f"   Code-fix log : {self.code_fix_log}")
        logger.info("   CWE + MITRE  : rule-based lookup tables, not from model")

    # ─────────────────────────────────────────────────────────────────────────
    # Main entry point (called by BaseAgent for each Kafka message)
    # ─────────────────────────────────────────────────────────────────────────

    def process_message(self, message):
        try:
            if self.test_limit > 0 and self.processed_count >= self.test_limit:
                logger.info(f"OLLAMA_TEST_LIMIT={self.test_limit} reached — stopping agent")
                self.cleanup()
                raise SystemExit(0)

            incident    = message
            incident_id = incident.get("incident_id")
            logger.info(f"🦙 Analysing {incident_id} with {self.model_name}…")

            analysis = self._analyse(incident)
            self.processed_count += 1

            logger.info(
                f"✅ [{self.processed_count}] {analysis['threat_type']} "
                f"(severity {analysis['severity']}, model: {analysis['model_used']})"
            )
            return analysis

        except SystemExit:
            raise
        except Exception as e:
            logger.error(f"process_message error: {e}")
            import traceback
            traceback.print_exc()
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Analysis pipeline
    # ─────────────────────────────────────────────────────────────────────────

    def _analyse(self, incident):
        alerts = incident.get("alerts", [])
        if not alerts:
            self.fallback_count += 1
            return self._empty_fallback(incident)

        first_alert = alerts[0]

        # Step 1: classify threat via keyword rules (fast, deterministic)
        threat_type = self._classify_threat_type(first_alert)

        # Step 2: CWE and MITRE from rule-based tables — never from the model
        cwe_id = THREAT_CWE.get(threat_type, str(first_alert.get("cwe_id", "0")))
        mitre_technique, mitre_tactic = THREAT_MITRE.get(threat_type, ("T1190", "Initial Access"))

        # Step 3: call Ollama only for severity, confidence, reasoning, and code_fix
        llm_result = self._call_ollama(incident, first_alert, threat_type)

        if llm_result is not None:
            severity   = max(1, min(10, int(llm_result.get("severity", 5))))
            confidence = max(0.0, min(1.0, float(llm_result.get("confidence", 0.7))))
            reasoning  = str(llm_result.get("reasoning", "")).strip()
            code_fix   = llm_result.get("code_fix") if threat_type in CODE_FIX_THREAT_TYPES else None
            model_used = self.model_name
            self.llm_success_count += 1
        else:
            sev_default, conf_default = THREAT_SEVERITY_DEFAULTS.get(threat_type, (6, 0.70))
            vuln_snippet = first_alert.get("vulnerability", "")[:60]
            severity   = sev_default
            confidence = conf_default
            reasoning  = f"Keyword fallback (Ollama unavailable): matched '{vuln_snippet}'"
            code_fix   = None
            model_used = "fallback-keyword-matching"
            self.fallback_count += 1

        analysis = {
            "analysis_id":       f"ANALYSIS-{incident.get('incident_id')}",
            "incident_id":       incident.get("incident_id"),
            "analyzed_at":       datetime.now().isoformat(),
            "threat_type":       threat_type,
            "cwe_id":            cwe_id,
            "severity":          severity,
            "confidence":        confidence,
            "mitre_technique":   mitre_technique,
            "mitre_tactic":      mitre_tactic,
            "reasoning":         reasoning,
            "immediate_actions": THREAT_ACTIONS.get(threat_type, ["alert_security_team"]),
            "original_incident": incident,
            "model_used":        model_used,
            "code_fix":          code_fix,
        }

        if code_fix and threat_type in CODE_FIX_THREAT_TYPES:
            self._write_code_fix_log(analysis, first_alert)

        return analysis

    # ─────────────────────────────────────────────────────────────────────────
    # Threat type classification — keyword rules, not the LLM
    # ─────────────────────────────────────────────────────────────────────────

    def _classify_threat_type(self, alert):
        vuln = alert.get("vulnerability", "").lower()
        desc = alert.get("description", "").lower()
        text = vuln + " " + desc

        if any(p in text for p in ["sql injection", "union select"]) or ("sql" in vuln):
            return "SQL Injection"
        if any(p in text for p in ["xss", "cross-site scripting", "script injection"]):
            return "Cross-Site Scripting (XSS)"
        if any(p in text for p in ["csrf", "cross-site request forgery"]):
            return "Cross-Site Request Forgery (CSRF)"
        if any(p in text for p in ["file upload", "arbitrary file"]):
            return "Arbitrary File Upload"
        if any(p in text for p in ["authentication", "bypass", "credential", "login"]):
            return "Authentication Bypass"
        if any(p in text for p in ["directory traversal", "path traversal", "../"]):
            return "Directory Traversal"
        if any(p in text for p in ["command injection", "os command"]):
            return "Command Injection"
        if any(p in text for p in ["information disclosure", "debug", "verbose error", "stack trace"]):
            return "Information Disclosure"
        if any(p in text for p in ["header", "x-frame", "content-security", "hsts", "x-content-type"]):
            return "Missing Security Headers"
        if any(p in text for p in ["xxe", "xml external entity"]):
            return "XML External Entity (XXE)"
        if any(p in text for p in ["ssrf", "server-side request forgery"]):
            return "Server-Side Request Forgery (SSRF)"
        return "Security Vulnerability"

    # ─────────────────────────────────────────────────────────────────────────
    # Ollama HTTP call
    # ─────────────────────────────────────────────────────────────────────────

    def _call_ollama(self, incident, alert, threat_type):
        prompt  = self._build_prompt(incident, alert, threat_type)
        payload = {
            "model":  self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        try:
            t0   = time.monotonic()
            resp = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=None,
            )
            elapsed = time.monotonic() - t0
            self.llm_call_times.append(elapsed)
            logger.info(f"   Ollama responded in {elapsed:.1f}s")

            if resp.status_code != 200:
                logger.warning(f"Ollama returned HTTP {resp.status_code} — using keyword fallback")
                return None

            raw = resp.json().get("response", "")
            return self._parse_response(raw)

        except requests.exceptions.ConnectionError:
            logger.warning(f"Ollama not reachable at {self.ollama_url} — using keyword fallback")
            return None
        except requests.exceptions.Timeout:
            logger.warning("Ollama connection timed out — using keyword fallback")
            return None
        except Exception as e:
            logger.error(f"Ollama call error: {e}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Prompt — asks the model only for what rules cannot provide
    # ─────────────────────────────────────────────────────────────────────────

    def _build_prompt(self, incident, alert, threat_type):
        needs_code_fix = threat_type in CODE_FIX_THREAT_TYPES

        code_fix_section = ""
        if needs_code_fix:
            code_fix_section = """,
  "code_fix": {
    "vulnerable_snippet": "<short illustrative example of the vulnerable code pattern>",
    "patched_snippet": "<corrected version of the same snippet>",
    "explanation": "<one sentence: why the fix eliminates the vulnerability>"
  }"""

        return f"""You are a web-application security analyst.

The vulnerability has already been classified as: {threat_type}
Do NOT change this classification or add cwe_id or mitre fields to your response.

Your task: assess severity, confidence, and explain the risk in plain English.
Return ONLY a single valid JSON object — no markdown fences, no extra text.

VULNERABILITY CONTEXT:
  Vulnerability : {alert.get('vulnerability', 'Unknown')}
  URL           : {alert.get('url', 'N/A')}
  ZAP Risk      : {alert.get('risk', alert.get('confidence', 'Unknown'))}
  CWE           : {alert.get('cwe_id', '0')}
  Alert count   : {incident.get('alert_count', 1)}
  Description   : {alert.get('description', '')[:300]}
  Evidence      : {alert.get('evidence', '')[:150]}

REQUIRED JSON STRUCTURE:
{{
  "severity": <integer 1-10>,
  "confidence": <float 0.0-1.0>,
  "reasoning": "<2-3 sentences: what an attacker could do and why this matters>"{code_fix_section}
}}

Severity guide:
  9-10 = critical (RCE, SQLi on login, auth bypass)
  7-8  = high (stored XSS, unrestricted upload, IDOR)
  4-6  = medium (reflected XSS, info disclosure, missing headers)
  1-3  = low (informational, best-practice gaps)

Return ONLY the JSON object."""

    # ─────────────────────────────────────────────────────────────────────────
    # Response parsing — validates and extracts only the fields we asked for
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_response(self, raw):
        try:
            text = raw.strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

            data = json.loads(text)

            severity   = max(1, min(10, int(data.get("severity", 5))))
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0.7))))
            reasoning  = str(data.get("reasoning", "")).strip()

            if not reasoning:
                logger.warning("Ollama response had no reasoning text — using fallback")
                return None

            result = {"severity": severity, "confidence": confidence, "reasoning": reasoning}

            code_fix = data.get("code_fix")
            if code_fix and isinstance(code_fix, dict):
                result["code_fix"] = code_fix

            return result

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.warning(f"Could not parse Ollama JSON: {e} — raw[:200]: {raw[:200]}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Empty fallback for incidents with no alert data
    # ─────────────────────────────────────────────────────────────────────────

    def _empty_fallback(self, incident):
        return {
            "analysis_id":       f"ANALYSIS-{incident.get('incident_id')}",
            "incident_id":       incident.get("incident_id"),
            "analyzed_at":       datetime.now().isoformat(),
            "threat_type":       "Security Vulnerability",
            "cwe_id":            "0",
            "severity":          5,
            "confidence":        0.5,
            "mitre_technique":   "T1190",
            "mitre_tactic":      "Initial Access",
            "reasoning":         "No alert data in incident — manual investigation required",
            "immediate_actions": ["alert_security_team"],
            "original_incident": incident,
            "model_used":        "fallback-empty",
            "code_fix":          None,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Code-fix log — developer suggestion, NEVER auto-applied
    # ─────────────────────────────────────────────────────────────────────────

    def _write_code_fix_log(self, analysis, alert):
        fix = analysis.get("code_fix", {})
        if not fix:
            return
        try:
            with open(self.code_fix_log, "a") as f:
                f.write(f"\n{'='*65}\n")
                f.write("OLLAMA CODE-FIX SUGGESTION — DEVELOPER REVIEW REQUIRED — NEVER AUTO-APPLIED\n")
                f.write(f"Timestamp  : {datetime.now().isoformat()}\n")
                f.write(f"Threat     : {analysis['threat_type']}  (Severity {analysis['severity']}/10)\n")
                f.write(f"CWE        : CWE-{analysis['cwe_id']}\n")
                f.write(f"URL        : {alert.get('url', 'N/A')}\n")
                f.write(f"Model      : {self.model_name}\n")
                f.write(f"Reasoning  : {analysis['reasoning']}\n")
                f.write(f"\nVULNERABLE PATTERN:\n{fix.get('vulnerable_snippet', 'N/A')}\n")
                f.write(f"\nSUGGESTED FIX:\n{fix.get('patched_snippet', 'N/A')}\n")
                f.write(f"\nWHY IT WORKS:\n{fix.get('explanation', 'N/A')}\n")
                f.write(f"{'='*65}\n")
            logger.info(f"   📝 Code-fix suggestion written to {self.code_fix_log}")
        except Exception as e:
            logger.error(f"Failed to write code-fix log: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Shutdown — prints truthful end-of-run summary
    # ─────────────────────────────────────────────────────────────────────────

    def cleanup(self):
        avg_time = (
            sum(self.llm_call_times) / len(self.llm_call_times)
            if self.llm_call_times else 0.0
        )
        logger.info(f"\n{'='*55}")
        logger.info("Ollama Analysis Agent — End-of-Run Summary")
        logger.info(f"{'='*55}")
        logger.info(f"Total processed   : {self.processed_count}")
        logger.info(f"LLM success       : {self.llm_success_count}  (Ollama responded with valid JSON)")
        logger.info(f"Keyword fallback  : {self.fallback_count}   (Ollama unreachable or invalid response)")
        logger.info(f"Model             : {self.model_name} at {self.ollama_url}")
        if self.llm_success_count > 0:
            logger.info(f"Avg LLM call time : {avg_time:.1f}s")
        else:
            logger.info("Avg LLM call time : n/a (no successful LLM calls)")
        logger.info(f"{'='*55}")
        super().cleanup()


if __name__ == "__main__":
    agent = OllamaAnalysisAgent()
    agent.run()
