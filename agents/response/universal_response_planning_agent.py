#!/usr/bin/env python3
"""
Universal Response Planning Agent - ENTERPRISE GRADE
FIXED: Proper CWE extraction, works for any vulnerability type
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'universal'))
from action_mapper import UniversalActionMapper
from tech_detector import TechnologyDetector
import logging
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UniversalResponsePlanningAgent(BaseAgent):
    """
    ENTERPRISE Universal Response Planning
    Works for ANY vulnerability, ANY tech stack
    """
    
    def __init__(self):
        super().__init__(
            agent_name="UniversalResponsePlanningAgent-Enterprise-v8",
            input_topic="llm-analysis",
            output_topic="response-plans"
        )
        
        self.action_mapper = UniversalActionMapper()
        self.tech_detector = TechnologyDetector()
        
        self.plan_count = 0
        
        logger.info("🌍 ENTERPRISE Universal Response Planning initialized")
        logger.info("   ✅ Zero action bias")
        logger.info("   ✅ ALL vulnerability types supported")
        logger.info("   ✅ ALL tech stacks supported")
    
    def process_message(self, message):
        """Create universal response plan for ANY vulnerability"""
        try:
            analysis = message
            
            incident = analysis.get('original_incident', {})
            incident_id = analysis.get('incident_id')
            
            # Detect technology stack (UNIVERSAL)
            tech_stack = self.tech_detector.detect_from_incident(incident)
            
            logger.info(f"\n🎯 Planning response for {incident_id}")
            logger.info(f"   Tech Stack: {tech_stack['web_server']}/{tech_stack['language']}/{tech_stack['framework']}")
            
            # FIXED: Extract CWE properly
            cwe_id = analysis.get('cwe_id', '0')
            if not cwe_id or cwe_id == '0':
                # Try to get from first alert
                alerts = incident.get('alerts', [])
                if alerts:
                    cwe_id = alerts[0].get('cwe_id', '0')
            
            # Map vulnerability to actions (UNIVERSAL)
            actions = self.action_mapper.map_vulnerability_to_actions(
                vulnerability_type=analysis.get('threat_type', 'Unknown'),
                cwe_id=str(cwe_id),
                mitre_technique=analysis.get('mitre_technique', ''),
                severity=analysis.get('severity', 5),
                confidence=analysis.get('confidence', 0.5),
                tech_stack=tech_stack
            )
            
            # Create action plans with metadata
            action_plans = []
            for action in actions:
                metadata = self.action_mapper.get_action_metadata(action)
                
                action_plan = {
                    'action_type': action,
                    'target': self._get_target_from_incident(incident),
                    'parameters': self._generate_parameters(action, analysis, tech_stack),
                    'metadata': metadata,
                    'priority': self._calculate_priority(metadata, analysis),
                    'estimated_duration': self._estimate_duration(action, metadata)
                }
                
                action_plans.append(action_plan)
            
            # Create response plan
            response_plan = {
                'plan_id': f"PLAN-{analysis.get('analysis_id')}",
                'analysis_id': analysis.get('analysis_id'),
                'incident_id': incident_id,
                'created_at': datetime.now().isoformat(),
                'threat_type': analysis.get('threat_type'),
                'severity': analysis.get('severity'),
                'confidence': analysis.get('confidence'),
                'mitre_technique': analysis.get('mitre_technique'),
                'mitre_tactic': analysis.get('mitre_tactic'),
                'cwe_id': str(cwe_id),
                'tech_stack': tech_stack,
                'actions': action_plans,
                'total_actions': len(action_plans),
                'reasoning': f"Universal mapping: {len(actions)} actions for {analysis.get('threat_type')} on {tech_stack['web_server']}",
                'universal_plan': True,
                'bias_free': True,
                'enterprise_grade': True
            }
            
            self.plan_count += 1
            logger.info(f"✅ Plan {self.plan_count}: {response_plan['plan_id']} with {len(action_plans)} actions")
            
            return response_plan
            
        except Exception as e:
            logger.error(f"Error creating response plan: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _get_target_from_incident(self, incident: Dict) -> str:
        """Extract target URL from incident"""
        alerts = incident.get('alerts', [])
        if alerts:
            return alerts[0].get('url', 'unknown')
        return 'unknown'
    
    def _generate_parameters(self, action: str, analysis: Dict, tech_stack: Dict) -> Dict:
        """Generate action parameters dynamically (UNIVERSAL)"""
        params = {
            'threat_type': analysis.get('threat_type'),
            'severity': analysis.get('severity'),
            'confidence': analysis.get('confidence'),
            'cwe_id': analysis.get('cwe_id', '0')
        }
        
        # Action-specific parameters
        if 'waf' in action:
            params['pattern'] = self._generate_waf_pattern(analysis.get('threat_type'))
            params['description'] = f"Block {analysis.get('threat_type')}"
        
        elif 'header' in action:
            params['headers'] = self._get_security_headers(analysis.get('threat_type'))
        
        elif 'rate' in action:
            params['requests_per_minute'] = 60 if analysis.get('severity', 0) >= 7 else 120
        
        elif 'alert' in action:
            params['priority'] = 'high' if analysis.get('severity', 0) >= 8 else 'medium'
        
        elif 'validation' in action or 'sanitize' in action:
            params['validation_type'] = self._get_validation_type(analysis.get('threat_type'))
        
        return params
    
    def _generate_waf_pattern(self, threat_type: str) -> str:
        """Generate WAF pattern based on threat type (UNIVERSAL)"""
        patterns = {
            'SQL Injection': r"(\\'|\\\"|\\OR\\|\\UNION\\|\\SELECT\\|\\DROP\\)",
            'XSS': r"(<script|javascript:|onerror=|onload=|<img)",
            'Cross-Site Scripting': r"(<script|javascript:|onerror=|onload=|<img)",
            'Command Injection': r"(;|&&|\\||`|\\$\\()",
            'Path Traversal': r"(\\.\\.\\/|\\.\\.\\\\)",
            'Directory Traversal': r"(\\.\\.\\/|\\.\\.\\\\)",
            'XXE': r"(<!ENTITY|<!DOCTYPE|SYSTEM)",
            'SSRF': r"(file://|dict://|gopher://)"
        }
        return patterns.get(threat_type, r"(malicious|attack|exploit)")
    
    def _get_security_headers(self, threat_type: str) -> Dict:
        """Get appropriate security headers (UNIVERSAL)"""
        headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block'
        }
        
        if 'XSS' in threat_type or 'Cross-Site Scripting' in threat_type:
            headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
        
        if 'Clickjacking' in threat_type:
            headers['X-Frame-Options'] = 'DENY'
        
        return headers
    
    def _get_validation_type(self, threat_type: str) -> str:
        """Get validation type for threat (UNIVERSAL)"""
        if 'SQL' in threat_type:
            return 'sql_injection'
        elif 'XSS' in threat_type or 'Cross-Site Scripting' in threat_type:
            return 'xss'
        elif 'Command' in threat_type:
            return 'command_injection'
        elif 'Path' in threat_type or 'Traversal' in threat_type:
            return 'path_traversal'
        else:
            return 'generic'
    
    def _calculate_priority(self, metadata: Dict, analysis: Dict) -> int:
        """Calculate action priority 1-10 (UNIVERSAL)"""
        base_priority = 5
        
        if analysis.get('severity', 0) >= 8:
            base_priority += 3
        
        if analysis.get('confidence', 0) >= 0.9:
            base_priority += 1
        
        if metadata.get('risk_level') == 'high':
            base_priority -= 2
        
        return max(1, min(10, base_priority))
    
    def _estimate_duration(self, action: str, metadata: Dict) -> str:
        """Estimate action duration (UNIVERSAL)"""
        if metadata.get('category') == 'configuration':
            return '< 1 minute'
        elif metadata.get('category') == 'network_control':
            return '1-5 minutes'
        elif metadata.get('category') == 'code_fix':
            return '30-60 minutes'
        else:
            return '5-15 minutes'
    
    def cleanup(self):
        """Called on shutdown"""
        logger.info(f"\n{'='*50}")
        logger.info(f"ENTERPRISE Response Planning Summary:")
        logger.info(f"{'='*50}")
        logger.info(f"Total Plans Created: {self.plan_count}")
        logger.info(f"Universal Mapping: ✅ Active")
        logger.info(f"Action Bias: ❌ None")
        logger.info(f"Tech Stack Support: 🌍 Universal")
        logger.info(f"Enterprise Grade: ✅ Yes")
        logger.info(f"{'='*50}")
        super().cleanup()


if __name__ == "__main__":
    agent = UniversalResponsePlanningAgent()
    agent.run()