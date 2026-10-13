#!/usr/bin/env python3
"""
AEGENTRA AI Analysis Agent — Gemini 1.5 Flash
Drop-in replacement for ai_analysis.py.
Same Kafka topics: reads correlated-incidents, writes llm-analysis.
Falls back to keyword matching if the API fails or GEMINI_API_KEY is not set.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
import json
import logging
import yaml
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    logger.warning("google-genai package not installed — will use keyword fallback for all messages")

# ─────────────────────────────────────────────────────────────────────────────
# Vocabulary constrained to what action_mapper.py understands exactly
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


class AIAnalysisAgent(BaseAgent):
    """
    AEGENTRA analysis agent backed by Gemini 1.5 Flash.
    Reads GEMINI_API_KEY from the environment — never hardcoded.
    Falls back to keyword pattern matching if the API call fails or key is absent.
    """

    def __init__(self):
        super().__init__(
            agent_name="AIAnalysisAgent-Gemini-1.5-Flash-v2",
            input_topic="correlated-incidents",
            output_topic="llm-analysis",
        )

        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            logger.warning("⚠️  GEMINI_API_KEY not set — Gemini API unavailable, using keyword fallback")
            logger.warning("    To enable LLM analysis: export GEMINI_API_KEY='your-key' and restart")
            self.model_client = None
        elif not GENAI_AVAILABLE:
            logger.warning("⚠️  google-genai not installed — using keyword fallback")
            self.model_client = None
        else:
            self.model_client = genai.Client(api_key=api_key)
            logger.info("✅ Gemini 1.5 Flash configured successfully")

        self.model_name = "gemini-2.5-flash"
        self.analyzed_count = 0
        self.api_failures = 0

        config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml")
        with open(config_path) as f:
            config = yaml.safe_load(f)
        self.code_fix_log = config.get("monitoring", {}).get(
            "code_fix_log", "/tmp/aegentra_code_fixes.log"
        )

        logger.info(f"✅ AI Analysis Agent initialised — model: {self.model_name}")
        logger.info(f"   Code-fix log: {self.code_fix_log}")
        logger.info("   Fallback: keyword pattern matching on API failure")

    # ─────────────────────────────────────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────────────────────────────────────

    def process_message(self, message):
        try:
            incident = message
            incident_id = incident.get("incident_id")
            logger.info(f"🤖 Analysing {incident_id} with {self.model_name}…")

            analysis = self._analyse(incident)

            self.analyzed_count += 1
            logger.info(
                f"✅ [{self.analyzed_count}] {analysis['threat_type']} "
                f"(severity {analysis['severity']}, "
                f"model: {analysis['model_used']})"
            )
            return analysis

        except Exception as e:
            logger.error(f"process_message error: {e}")
            import traceback
            traceback.print_exc()
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Gemini call
    # ─────────────────────────────────────────────────────────────────────────

    def _analyse(self, incident):
        alerts = incident.get("alerts", [])
        if not alerts:
            return self._empty_fallback(incident)

        first_alert = alerts[0]

        if not self.model_client:
            logger.warning("Gemini client unavailable — using keyword fallback")
            self.api_failures += 1
            return self._keyword_fallback(incident, first_alert)

        try:
            prompt = self._build_prompt(incident, first_alert)
            response = self.model_client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            raw = response.text

            parsed = self._parse_response(raw, incident, first_alert)

            if parsed is None:
                logger.warning("Could not parse Gemini response — using keyword fallback")
                self.api_failures += 1
                return self._keyword_fallback(incident, first_alert)

            if parsed.get("code_fix") and parsed["threat_type"] in CODE_FIX_THREAT_TYPES:
                self._write_code_fix_log(parsed, first_alert)

            return parsed

        except Exception as e:
            err_str = str(e)
            if '429' in err_str or 'RESOURCE_EXHAUSTED' in err_str:
                # Quota exhausted — fall back immediately, do not retry
                logger.warning("Gemini quota exhausted — switching to keyword fallback for this session")
                self.model_client = None  # disable further API calls this session
            else:
                logger.error(f"Gemini API error: {e}")
            self.api_failures += 1
            return self._keyword_fallback(incident, first_alert)

    # ─────────────────────────────────────────────────────────────────────────
    # Prompt construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_prompt(self, incident, alert):
        threat_list = "\n".join(f"  - {t}" for t in ALLOWED_THREAT_TYPES)
        mitre_list  = "\n".join(f"  - {k}: {v}" for k, v in ALLOWED_MITRE.items())

        vuln_text = alert.get("vulnerability", "Unknown")
        needs_code_fix = any(
            kw in vuln_text.lower()
            for kw in ["sql", "xss", "cross-site scripting", "csrf", "cross-site request forgery"]
        )

        code_fix_section = ""
        if needs_code_fix:
            code_fix_section = """,
  "code_fix": {
    "vulnerable_snippet": "<short illustrative example of the vulnerable code pattern>",
    "patched_snippet": "<corrected version of the same snippet>",
    "explanation": "<one sentence: why the fix eliminates the vulnerability>"
  }"""

        return f"""You are a web-application security analyst.
Analyse the vulnerability incident below and return ONLY a single valid JSON object — no markdown fences, no extra text.

INCIDENT
  Vulnerability : {vuln_text}
  URL           : {alert.get('url', 'N/A')}
  ZAP Risk      : {alert.get('risk', alert.get('confidence', 'Unknown'))}
  CWE ID        : {alert.get('cwe_id', '0')}
  Alert count   : {incident.get('alert_count', 1)}
  Description   : {alert.get('description', '')[:300]}
  Evidence      : {alert.get('evidence', '')[:150]}

REQUIRED JSON STRUCTURE:
{{
  "threat_type": "<exactly one value from the allowed list>",
  "cwe_id": "<integer as string, e.g. \\"89\\">",
  "severity": <integer 1-10>,
  "confidence": <float 0.0-1.0>,
  "mitre_technique": "<T-code from allowed list>",
  "mitre_tactic": "<tactic name matching the T-code>",
  "reasoning": "<2-3 sentences: what the threat is, why it is risky, what an attacker could do>"{code_fix_section}
}}

ALLOWED threat_type values (use the string exactly):
{threat_list}

ALLOWED mitre_technique values:
{mitre_list}

Rules:
- severity 9-10 = critical (RCE, SQLi on login, auth bypass)
- severity 7-8  = high (stored XSS, unrestricted upload, IDOR)
- severity 4-6  = medium (reflected XSS, info disclosure, missing headers)
- severity 1-3  = low (informational, best-practice gaps)
- confidence reflects how certain you are given the evidence provided
- If the vulnerability does not match any specific category use "Security Vulnerability"
- Return ONLY the JSON object."""

    # ─────────────────────────────────────────────────────────────────────────
    # Response parsing
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_response(self, raw, incident, alert):
        try:
            text = raw.strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

            data = json.loads(text)

            threat_type = data.get("threat_type", "Security Vulnerability")
            if threat_type not in ALLOWED_THREAT_TYPES:
                logger.warning(f"Unknown threat_type '{threat_type}' — defaulting to Security Vulnerability")
                threat_type = "Security Vulnerability"

            mitre_technique = data.get("mitre_technique", "Unknown")
            if mitre_technique not in ALLOWED_MITRE:
                mitre_technique = "Unknown"
            mitre_tactic = ALLOWED_MITRE.get(mitre_technique, data.get("mitre_tactic", "Unknown"))

            severity = int(data.get("severity", 5))
            severity = max(1, min(10, severity))

            confidence = float(data.get("confidence", 0.7))
            confidence = max(0.0, min(1.0, confidence))

            return {
                "analysis_id":       f"ANALYSIS-{incident.get('incident_id')}",
                "incident_id":       incident.get("incident_id"),
                "analyzed_at":       datetime.now().isoformat(),
                "threat_type":       threat_type,
                "cwe_id":            str(data.get("cwe_id", alert.get("cwe_id", "0"))),
                "severity":          severity,
                "confidence":        confidence,
                "mitre_technique":   mitre_technique,
                "mitre_tactic":      mitre_tactic,
                "reasoning":         data.get("reasoning", ""),
                "immediate_actions": THREAT_ACTIONS.get(threat_type, ["alert_security_team"]),
                "original_incident": incident,
                "model_used":        self.model_name,
                "code_fix":          data.get("code_fix"),
            }

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.error(f"Response parse error: {e}\nRaw: {raw[:200]}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Code-fix log — human review only, never auto-applied
    # ─────────────────────────────────────────────────────────────────────────

    def _write_code_fix_log(self, analysis, alert):
        fix = analysis.get("code_fix", {})
        if not fix:
            return
        try:
            with open(self.code_fix_log, "a") as f:
                f.write(f"\n{'='*65}\n")
                f.write("AI CODE-FIX SUGGESTION — HUMAN REVIEW REQUIRED — NEVER AUTO-APPLIED\n")
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
    # Keyword fallback — pipeline never dies even without an API key
    # ─────────────────────────────────────────────────────────────────────────

    def _keyword_fallback(self, incident, alert):
        vuln = alert.get("vulnerability", "").lower()
        desc = alert.get("description", "").lower()

        if any(p in vuln or p in desc for p in ["sql injection", "sql", "union select"]):
            threat, sev, conf, mitre, tactic = "SQL Injection", 9, 0.95, "T1190", "Initial Access"
        elif any(p in vuln or p in desc for p in ["xss", "cross-site scripting", "script"]):
            threat, sev, conf, mitre, tactic = "Cross-Site Scripting (XSS)", 8, 0.90, "T1189", "Execution"
        elif any(p in vuln for p in ["csrf", "cross-site request forgery"]):
            threat, sev, conf, mitre, tactic = "Cross-Site Request Forgery (CSRF)", 7, 0.85, "T1566", "Initial Access"
        elif any(p in vuln for p in ["file upload", "upload", "arbitrary file"]):
            threat, sev, conf, mitre, tactic = "Arbitrary File Upload", 8, 0.85, "T1505", "Persistence"
        elif any(p in vuln for p in ["authentication", "login", "bypass", "credential"]):
            threat, sev, conf, mitre, tactic = "Authentication Bypass", 9, 0.90, "T1078", "Defense Evasion"
        elif any(p in vuln for p in ["directory traversal", "path traversal", "../"]):
            threat, sev, conf, mitre, tactic = "Directory Traversal", 7, 0.85, "T1083", "Discovery"
        elif any(p in vuln for p in ["command injection", "os command", "exec"]):
            threat, sev, conf, mitre, tactic = "Command Injection", 9, 0.95, "T1059", "Execution"
        elif any(p in vuln for p in ["information disclosure", "debug", "verbose", "error"]):
            threat, sev, conf, mitre, tactic = "Information Disclosure", 5, 0.80, "T1083", "Discovery"
        elif any(p in vuln for p in ["header", "x-frame", "content-security", "hsts", "x-content"]):
            threat, sev, conf, mitre, tactic = "Missing Security Headers", 4, 0.75, "T1190", "Initial Access"
        elif any(p in vuln for p in ["xxe", "xml external entity"]):
            threat, sev, conf, mitre, tactic = "XML External Entity (XXE)", 8, 0.90, "T1190", "Initial Access"
        elif any(p in vuln for p in ["ssrf", "server-side request forgery"]):
            threat, sev, conf, mitre, tactic = "Server-Side Request Forgery (SSRF)", 8, 0.90, "T1090", "Command and Control"
        else:
            threat, sev, conf, mitre, tactic = "Security Vulnerability", 6, 0.70, "Unknown", "Unknown"

        return {
            "analysis_id":       f"ANALYSIS-{incident.get('incident_id')}",
            "incident_id":       incident.get("incident_id"),
            "analyzed_at":       datetime.now().isoformat(),
            "threat_type":       threat,
            "cwe_id":            str(alert.get("cwe_id", "0")),
            "severity":          sev,
            "confidence":        conf,
            "mitre_technique":   mitre,
            "mitre_tactic":      tactic,
            "reasoning":         f"Fallback (API unavailable): pattern matched '{vuln[:60]}'",
            "immediate_actions": THREAT_ACTIONS.get(threat, ["alert_security_team"]),
            "original_incident": incident,
            "model_used":        "fallback-keyword-matching",
            "code_fix":          None,
        }

    def _empty_fallback(self, incident):
        return {
            "analysis_id":       f"ANALYSIS-{incident.get('incident_id')}",
            "incident_id":       incident.get("incident_id"),
            "analyzed_at":       datetime.now().isoformat(),
            "threat_type":       "Security Vulnerability",
            "cwe_id":            "0",
            "severity":          5,
            "confidence":        0.5,
            "mitre_technique":   "Unknown",
            "mitre_tactic":      "Unknown",
            "reasoning":         "No alert data in incident — manual investigation required",
            "immediate_actions": ["alert_security_team"],
            "original_incident": incident,
            "model_used":        "fallback-empty",
            "code_fix":          None,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Shutdown summary
    # ─────────────────────────────────────────────────────────────────────────

    def cleanup(self):
        logger.info(f"\n{'='*50}")
        logger.info("AI Analysis Agent (Gemini) Summary")
        logger.info(f"{'='*50}")
        logger.info(f"Total analysed : {self.analyzed_count}")
        logger.info(f"API failures   : {self.api_failures} (fell back to keyword matching)")
        logger.info(f"Model          : {self.model_name}")
        logger.info(f"{'='*50}")
        super().cleanup()


if __name__ == "__main__":
    agent = AIAnalysisAgent()
    agent.run()
