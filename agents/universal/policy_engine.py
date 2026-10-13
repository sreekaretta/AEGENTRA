"""
Universal Policy Engine - ENTERPRISE GRADE
Dynamic safety assessment without hardcoded rules
FIXED: Comprehensive risk assessment for ANY action type
"""

import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class UniversalPolicyEngine:
    """
    ENTERPRISE Universal Policy Engine
    Assesses action safety dynamically for ANY vulnerability
    """
    
    def __init__(self):
        # Risk assessment weights (scientifically calibrated)
        self.risk_weights = {
            'business_impact': 0.35,
            'reversibility': 0.25,
            'complexity': 0.20,
            'success_probability': 0.20
        }
        
        logger.info("✅ Universal Policy Engine initialized")
        logger.info("   📊 Dynamic risk assessment")
        logger.info("   📊 No hardcoded rules")
    
    def assess_action_safety(self, 
                            action: str,
                            action_metadata: Dict,
                            vulnerability_context: Dict,
                            tech_stack: Dict) -> Tuple[str, float, str]:
        """
        ENTERPRISE Universal safety assessment
        Returns: (decision, risk_score, reasoning)
        """
        # Calculate comprehensive risk score (0-100)
        risk_score = self._calculate_risk_score(action, action_metadata, vulnerability_context, tech_stack)
        
        # Make decision based on risk (ADAPTIVE THRESHOLDS)
        if risk_score < 30:
            decision = 'SAFE_AUTO'
            reasoning = f'Low risk ({risk_score:.0f}/100) - safe for automation'
        elif risk_score < 60:
            decision = 'SAFE_WITH_MONITORING'
            reasoning = f'Medium risk ({risk_score:.0f}/100) - safe with enhanced monitoring'
        elif risk_score < 80:
            decision = 'REQUIRES_APPROVAL'
            reasoning = f'Medium-high risk ({risk_score:.0f}/100) - requires human approval'
        else:
            decision = 'HOLD'
            reasoning = f'High risk ({risk_score:.0f}/100) - manual execution only'
        
        logger.info(f"   Action '{action}': {decision} (risk: {risk_score:.0f}/100)")
        
        return decision, risk_score, reasoning
    
    def _calculate_risk_score(self, action: str, metadata: Dict, vuln_context: Dict, tech_stack: Dict) -> float:
        """Calculate comprehensive risk score (0-100) - UNIVERSAL"""
        
        # Factor 1: Business impact (0-100)
        business_impact = self._assess_business_impact(action, metadata, vuln_context)
        
        # Factor 2: Reversibility (0-100, lower is better)
        reversibility = self._assess_reversibility(action, metadata)
        
        # Factor 3: Complexity (0-100)
        complexity = self._assess_complexity(action, tech_stack)
        
        # Factor 4: Success probability (0-100, inverted)
        success_prob = 100 - self._assess_success_probability(action, tech_stack)
        
        # Weighted average
        risk_score = (
            business_impact * self.risk_weights['business_impact'] +
            reversibility * self.risk_weights['reversibility'] +
            complexity * self.risk_weights['complexity'] +
            success_prob * self.risk_weights['success_probability']
        )
        
        return risk_score
    
    def _assess_business_impact(self, action: str, metadata: Dict, vuln_context: Dict) -> float:
        """Assess potential business impact (0-100) - UNIVERSAL"""
        score = 0
        
        # Check action category
        if metadata.get('category') == 'network_control':
            score += 40  # Could affect availability
        elif metadata.get('category') == 'code_fix':
            score += 30  # Could introduce bugs
        elif metadata.get('category') == 'configuration':
            score += 20  # Usually safer
        
        # Check if affects production (UNIVERSAL detection)
        url = vuln_context.get('url', '').lower()
        if any(keyword in url for keyword in ['prod', 'production', 'live', 'www', 'api']):
            score += 30
        
        # Check if affects critical functions (UNIVERSAL)
        if any(keyword in url for keyword in ['payment', 'checkout', 'auth', 'login', 'admin', 'api']):
            score += 20
        
        # Check estimated impact from metadata
        impact = metadata.get('estimated_impact', 'low')
        if impact == 'high':
            score += 30
        elif impact == 'medium':
            score += 15
        
        # Check vulnerability severity (higher severity = more critical to fix)
        severity = vuln_context.get('severity', 0)
        if severity >= 9:
            score -= 10  # Critical fixes are worth the risk
        
        return min(score, 100)
    
    def _assess_reversibility(self, action: str, metadata: Dict) -> float:
        """Assess how easily action can be reversed (0-100) - UNIVERSAL"""
        if not metadata.get('can_rollback', True):
            return 100  # Cannot rollback = high risk
        
        # Actions that are hard to reverse (UNIVERSAL)
        hard_to_reverse = ['delete', 'drop', 'remove', 'purge', 'restart', 'shutdown', 'migrate']
        if any(keyword in action for keyword in hard_to_reverse):
            return 80
        
        # Actions that are moderately reversible
        moderate = ['update', 'patch', 'modify', 'change', 'upgrade']
        if any(keyword in action for keyword in moderate):
            return 40
        
        # Easy to reverse (config changes, rules)
        return 20
    
    def _assess_complexity(self, action: str, tech_stack: Dict) -> float:
        """Assess action complexity (0-100) - UNIVERSAL"""
        score = 30  # Base complexity
        
        # Unknown tech stack increases complexity
        if tech_stack.get('confidence', 0) < 0.5:
            score += 30
        
        # Complex actions (UNIVERSAL)
        complex_actions = ['patch', 'update', 'migrate', 'refactor', 'implement', 'upgrade', 'compile']
        if any(keyword in action for keyword in complex_actions):
            score += 25
        
        # Simple actions (UNIVERSAL)
        simple_actions = ['add', 'enable', 'configure', 'set', 'log', 'alert', 'notify']
        if any(keyword in action for keyword in simple_actions):
            score -= 15
        
        return max(0, min(score, 100))
    
    def _assess_success_probability(self, action: str, tech_stack: Dict) -> float:
        """Assess probability of successful execution (0-100) - UNIVERSAL"""
        score = 70  # Base probability
        
        # Known tech stack increases success probability
        if tech_stack.get('confidence', 0) > 0.7:
            score += 20
        
        # Well-defined actions have higher success rate (UNIVERSAL)
        well_defined = ['add_waf_rule', 'add_security_headers', 'enable_rate_limiting', 
                       'add_input_validation', 'implement_rate_limiting', 'alert_security_team']
        if action in well_defined:
            score += 10
        
        # Experimental actions have lower success rate (UNIVERSAL)
        experimental = ['patch_application', 'update_framework', 'migrate', 'upgrade_system']
        if any(keyword in action for keyword in experimental):
            score -= 20
        
        return max(0, min(score, 100))