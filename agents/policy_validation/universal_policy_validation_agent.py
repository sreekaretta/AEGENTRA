#!/usr/bin/env python3
"""
Universal Policy Validation Agent - ENTERPRISE GRADE
Dynamic safety assessment without hardcoded rules
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'universal'))
from policy_engine import UniversalPolicyEngine
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UniversalPolicyValidationAgent(BaseAgent):
    """
    ENTERPRISE Universal Policy Validation
    Works for ANY action, ANY vulnerability, ANY tech stack
    """
    
    def __init__(self):
        super().__init__(
            agent_name="UniversalPolicyValidationAgent-Enterprise-v11",
            input_topic="response-plans",
            output_topic="policy-decisions"
        )
        
        self.policy_engine = UniversalPolicyEngine()
        
        self.decision_count = 0
        self.approved_count = 0
        self.hold_count = 0
        
        logger.info("🌍 ENTERPRISE Universal Policy Validation initialized")
        logger.info("   ✅ Dynamic risk assessment")
        logger.info("   ✅ No hardcoded rules")
        logger.info("   ✅ Context-aware decisions")
        logger.info("   ✅ Works for ANY vulnerability type")
    
    def process_message(self, message):
        """Validate plan with universal policy engine"""
        try:
            plan = message
            
            plan_id = plan.get('plan_id')
            actions = plan.get('actions', [])
            tech_stack = plan.get('tech_stack', {})
            
            logger.info(f"\n🔍 Validating {plan_id} ({len(actions)} actions)")
            
            # Assess each action (UNIVERSAL)
            action_assessments = []
            for action_plan in actions:
                action = action_plan.get('action_type')
                metadata = action_plan.get('metadata', {})
                
                decision, risk_score, reasoning = self.policy_engine.assess_action_safety(
                    action=action,
                    action_metadata=metadata,
                    vulnerability_context={
                        'threat_type': plan.get('threat_type'),
                        'severity': plan.get('severity'),
                        'confidence': plan.get('confidence'),
                        'url': action_plan.get('target'),
                        'cwe_id': plan.get('cwe_id', '0')
                    },
                    tech_stack=tech_stack
                )
                
                action_assessments.append({
                    'action': action,
                    'decision': decision,
                    'risk_score': risk_score,
                    'reasoning': reasoning
                })
            
            # Determine overall decision (UNIVERSAL)
            decisions = [a['decision'] for a in action_assessments]
            
            if all(d in ['SAFE_AUTO', 'SAFE_WITH_MONITORING'] for d in decisions):
                overall_decision = 'APPROVED'
                self.approved_count += 1
            else:
                overall_decision = 'HOLD'
                self.hold_count += 1
            
            # Create policy decision
            policy_decision = {
                'decision_id': f"DECISION-{plan_id}",
                'plan_id': plan_id,
                'incident_id': plan.get('incident_id'),
                'decided_at': datetime.now().isoformat(),
                'overall_decision': overall_decision,
                'action_assessments': action_assessments,
                'total_actions': len(actions),
                'safe_actions': len([d for d in decisions if d in ['SAFE_AUTO', 'SAFE_WITH_MONITORING']]),
                'risky_actions': len([d for d in decisions if d in ['REQUIRES_APPROVAL', 'HOLD']]),
                'average_risk_score': sum(a['risk_score'] for a in action_assessments) / len(action_assessments) if action_assessments else 0,
                'original_plan': plan,
                'universal_validation': True,
                'dynamic_assessment': True,
                'enterprise_grade': True
            }
            
            self.decision_count += 1
            
            if overall_decision == 'APPROVED':
                logger.info(f"✅ APPROVED {self.decision_count}: {plan_id} - All actions safe")
            else:
                logger.info(f"⏸️  HOLD {self.decision_count}: {plan_id} - {policy_decision['risky_actions']} risky actions")
            
            return policy_decision
            
        except Exception as e:
            logger.error(f"Error validating policy: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def cleanup(self):
        """Called on shutdown"""
        total = self.approved_count + self.hold_count
        logger.info(f"\n{'='*50}")
        logger.info(f"ENTERPRISE Policy Validation Summary:")
        logger.info(f"{'='*50}")
        logger.info(f"Total Decisions: {self.decision_count}")
        logger.info(f"Approved (Auto): {self.approved_count} ({(self.approved_count/total*100) if total > 0 else 0:.1f}%)")
        logger.info(f"Hold (Human): {self.hold_count} ({(self.hold_count/total*100) if total > 0 else 0:.1f}%)")
        logger.info(f"Dynamic Assessment: ✅ Active")
        logger.info(f"Hardcoded Rules: ❌ None")
        logger.info(f"Enterprise Grade: ✅ Yes")
        logger.info(f"{'='*50}")
        super().cleanup()


if __name__ == "__main__":
    agent = UniversalPolicyValidationAgent()
    agent.run()