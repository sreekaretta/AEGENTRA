#!/usr/bin/env python3
"""
AEGENTRA AI Analysis Agent - ENTERPRISE GRADE
FIXED: Added CWE extraction, universal vulnerability classification
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
import json
import logging
from datetime import datetime
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AIAnalysisAgent(BaseAgent):
    """ENTERPRISE AI Analysis - Works for ANY vulnerability type"""
    
    def __init__(self):
        super().__init__(
            agent_name="AIAnalysisAgent-Enterprise-v10",
            input_topic="correlated-incidents",
            output_topic="llm-analysis"
        )
        
        self.model = "glm-4-direct"
        self.analyzed_count = 0
        
        logger.info("✅ Enterprise AI Analysis configured")
        logger.info("   🌍 UNIVERSAL vulnerability classification")
        logger.info("   🔒 Works for any target, any tech stack")
    
    def process_message(self, message):
        """Analyze incident universally"""
        try:
            incident = message
            incident_id = incident.get('incident_id')
            
            logger.info(f"🔍 Analyzing {incident_id}...")
            
            analysis = self.analyze_incident_universally(incident)
            
            self.analyzed_count += 1
            logger.info(f"✅ Analysis {self.analyzed_count}: {analysis.get('threat_type')} (severity: {analysis.get('severity')})")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return None
    
    def analyze_incident_universally(self, incident):
        """UNIVERSAL analysis - works for any vulnerability"""
        
        alerts = incident.get('alerts', [])
        if not alerts:
            return self.create_fallback_analysis(incident)
        
        first_alert = alerts[0]
        vulnerability = first_alert.get('vulnerability', '').lower()
        url = first_alert.get('url', '')
        description = first_alert.get('description', '').lower()
        
        # FIXED: Extract CWE ID
        cwe_id = first_alert.get('cwe_id', '0')
        if cwe_id == '0' or cwe_id == 0:
            # Try to extract from description
            cwe_match = re.search(r'CWE-(\d+)', description, re.IGNORECASE)
            if cwe_match:
                cwe_id = cwe_match.group(1)
        
        # Classify vulnerability (UNIVERSAL)
        threat_type, severity, confidence, mitre_tech, mitre_tactic = self.classify_vulnerability(
            vulnerability, description, url
        )
        
        # Generate actions (UNIVERSAL)
        immediate_actions = self.generate_actions(threat_type, severity, url)
        
        # Generate reasoning
        reasoning = self.generate_reasoning(threat_type, severity, vulnerability)
        
        return {
            'analysis_id': f"ANALYSIS-{incident.get('incident_id')}",
            'incident_id': incident.get('incident_id'),
            'analyzed_at': datetime.now().isoformat(),
            'threat_type': threat_type,
            'severity': severity,
            'confidence': confidence,
            'mitre_technique': mitre_tech,
            'mitre_tactic': mitre_tactic,
            'cwe_id': str(cwe_id),  # FIXED: Include CWE
            'immediate_actions': immediate_actions,
            'reasoning': reasoning,
            'original_incident': incident,
            'model_used': 'enterprise-pattern-matching'
        }
    
    def classify_vulnerability(self, vulnerability, description, url):
        """UNIVERSAL vulnerability classification"""
        
        # SQL Injection (CWE-89)
        sql_patterns = ['sql injection', 'sql', 'union', 'select', 'insert', 'update', 'delete', 'drop']
        if any(pattern in vulnerability for pattern in sql_patterns) or any(pattern in description for pattern in sql_patterns):
            return 'SQL Injection', 9, 0.95, 'T1190', 'Initial Access'
        
        # XSS (CWE-79)
        xss_patterns = ['xss', 'cross-site scripting', 'script', 'javascript', 'html injection']
        if any(pattern in vulnerability for pattern in xss_patterns) or any(pattern in description for pattern in xss_patterns):
            return 'Cross-Site Scripting (XSS)', 8, 0.90, 'T1189', 'Execution'
        
        # CSRF (CWE-352)
        csrf_patterns = ['csrf', 'cross-site request forgery']
        if any(pattern in vulnerability for pattern in csrf_patterns):
            return 'Cross-Site Request Forgery (CSRF)', 7, 0.85, 'T1566', 'Initial Access'
        
        # Authentication (CWE-287)
        auth_patterns = ['authentication', 'login', 'password', 'credential', 'bypass']
        if any(pattern in vulnerability for pattern in auth_patterns):
            return 'Authentication Bypass', 9, 0.90, 'T1078', 'Defense Evasion'
        
        # File Upload (CWE-434)
        upload_patterns = ['file upload', 'upload', 'arbitrary file']
        if any(pattern in vulnerability for pattern in upload_patterns):
            return 'Arbitrary File Upload', 8, 0.85, 'T1505', 'Persistence'
        
        # Information Disclosure (CWE-200)
        info_patterns = ['information disclosure', 'information leak', 'debug', 'error', 'verbose']
        if any(pattern in vulnerability for pattern in info_patterns):
            return 'Information Disclosure', 5, 0.80, 'T1083', 'Discovery'
        
        # Security Headers (CWE-16)
        header_patterns = ['header', 'security header', 'x-frame', 'content-security', 'hsts']
        if any(pattern in vulnerability for pattern in header_patterns):
            return 'Missing Security Headers', 4, 0.75, 'T1190', 'Initial Access'
        
        # Path Traversal (CWE-22)
        dir_patterns = ['directory traversal', 'path traversal', 'file path', '../']
        if any(pattern in vulnerability for pattern in dir_patterns):
            return 'Directory Traversal', 7, 0.85, 'T1083', 'Discovery'
        
        # Command Injection (CWE-78)
        cmd_patterns = ['command injection', 'os command', 'system', 'exec']
        if any(pattern in vulnerability for pattern in cmd_patterns):
            return 'Command Injection', 9, 0.95, 'T1059', 'Execution'
        
        # XXE (CWE-611)
        xxe_patterns = ['xxe', 'xml external entity', 'xml injection']
        if any(pattern in vulnerability for pattern in xxe_patterns):
            return 'XML External Entity (XXE)', 8, 0.90, 'T1190', 'Initial Access'
        
        # SSRF (CWE-918)
        ssrf_patterns = ['ssrf', 'server-side request forgery']
        if any(pattern in vulnerability for pattern in ssrf_patterns):
            return 'Server-Side Request Forgery (SSRF)', 8, 0.90, 'T1090', 'Command and Control'
        
        # Default
        return 'Security Vulnerability', 6, 0.70, 'Unknown', 'Unknown'
    
    def generate_actions(self, threat_type, severity, url):
        """Generate appropriate actions (UNIVERSAL)"""
        actions = ['alert_security_team']
        
        if severity >= 8:
            actions.extend(['create_incident_ticket', 'enable_enhanced_monitoring'])
        
        if 'sql injection' in threat_type.lower():
            actions.extend(['use_prepared_statements', 'add_input_validation', 'add_waf_rule'])
        elif 'xss' in threat_type.lower():
            actions.extend(['add_output_encoding', 'add_content_security_policy', 'sanitize_user_inputs'])
        elif 'csrf' in threat_type.lower():
            actions.extend(['implement_csrf_tokens', 'validate_origin', 'add_samesite_cookies'])
        elif 'authentication' in threat_type.lower():
            actions.extend(['strengthen_authentication', 'add_mfa', 'implement_rate_limiting'])
        elif 'file upload' in threat_type.lower():
            actions.extend(['validate_file_types', 'scan_uploads', 'restrict_file_execution'])
        elif 'information disclosure' in threat_type.lower():
            actions.extend(['remove_verbose_errors', 'sanitize_responses', 'add_security_headers'])
        elif 'security header' in threat_type.lower():
            actions.extend(['add_security_headers', 'configure_web_server', 'update_response_headers'])
        elif 'directory traversal' in threat_type.lower():
            actions.extend(['validate_file_paths', 'implement_whitelist', 'restrict_file_access'])
        elif 'command injection' in threat_type.lower():
            actions.extend(['sanitize_command_inputs', 'use_safe_apis', 'implement_input_validation'])
        
        return actions[:5]
    
    def generate_reasoning(self, threat_type, severity, vulnerability):
        """Generate reasoning (UNIVERSAL)"""
        reasoning = f"Detected {threat_type} with severity {severity}/10. "
        
        if severity >= 8:
            reasoning += "Critical vulnerability requiring immediate attention. "
        elif severity >= 6:
            reasoning += "High-risk vulnerability requiring prompt action. "
        else:
            reasoning += "Medium-risk vulnerability for configuration fixes. "
        
        reasoning += f"Pattern matching identified '{vulnerability}' as {threat_type}."
        
        return reasoning
    
    def create_fallback_analysis(self, incident):
        """Fallback for insufficient data"""
        return {
            'analysis_id': f"ANALYSIS-{incident.get('incident_id')}",
            'incident_id': incident.get('incident_id'),
            'analyzed_at': datetime.now().isoformat(),
            'threat_type': 'Unknown Security Issue',
            'severity': 5,
            'confidence': 0.5,
            'mitre_technique': 'Unknown',
            'mitre_tactic': 'Unknown',
            'cwe_id': '0',
            'immediate_actions': ['investigate', 'monitor'],
            'reasoning': 'Insufficient data - manual investigation required',
            'original_incident': incident,
            'model_used': 'fallback'
        }
    
    def cleanup(self):
        """Cleanup"""
        logger.info(f"\n✅ Total incidents analyzed: {self.analyzed_count}")
        logger.info("🌍 Enterprise-grade universal analysis complete!")
        super().cleanup()


if __name__ == "__main__":
    agent = AIAnalysisAgent()
    agent.run()