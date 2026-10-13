import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebMonitoringAgent(BaseAgent):
    """
    Smart Web Monitoring Agent with Filtered Alerts Topic
    ENTERPRISE-GRADE: Works with ANY vulnerability scanner output
    """
    
    def __init__(self):
        super().__init__(
            agent_name="WebMonitor-Enterprise-v9",
            input_topic="web-detection-alerts",
            output_topic="unified-alerts"
        )
        
        # Safe low-severity vulnerabilities (config-only fixes)
        # UNIVERSAL: Works for any web application stack
        self.safe_low_severity = [
            'X-Content-Type-Options Header Missing',
            'X-Frame-Options Header Not Set',
            'X-XSS-Protection Header Not Set',
            'Strict-Transport-Security Header Not Set',
            'Content-Security-Policy Header Missing',
            'Directory Browsing',
            'Server Leaks Version Information',
            'Cookie Without Secure Flag',
            'Cookie Without HttpOnly Flag',
            'Missing Anti-clickjacking Header',
            'Referrer Policy Header Not Set',
            'Permissions Policy Header Not Set'
        ]
        
        self.stats = {
            'total': 0,
            'high_medium': 0,
            'safe_low': 0,
            'filtered': 0
        }
    
    def process_message(self, message):
        """
        UNIVERSAL filtering: Works for any target, any vulnerability type
        """
        self.stats['total'] += 1
        
        try:
            severity = message.get('severity', 0)
            vulnerability = message.get('vulnerability', '')
            
            # RULE 1: High/Medium severity - always forward (UNIVERSAL)
            if severity >= 2:
                self.stats['high_medium'] += 1
                message['detection_source'] = 'web'
                message['automation_reason'] = 'high_medium_severity'
                
                logger.info(
                    f"✅ HIGH/MED: {vulnerability[:50]} "
                    f"(severity: {severity}) [{self.stats['high_medium']}]"
                )
                return message
            
            # RULE 2: Low severity BUT safe to automate (UNIVERSAL)
            elif self.is_safe_low_severity(vulnerability):
                self.stats['safe_low'] += 1
                message['detection_source'] = 'web'
                message['automation_reason'] = 'safe_config_fix'
                
                logger.info(
                    f"✅ SAFE-LOW: {vulnerability[:50]} "
                    f"(severity: {severity}) [{self.stats['safe_low']}]"
                )
                return message
            
            # RULE 3: Low severity and NOT safe - filter
            else:
                self.stats['filtered'] += 1
                
                filtered_alert = {
                    'original_alert': message,
                    'filtered_at': datetime.now().isoformat(),
                    'filter_reason': 'Low severity + not safe for automation',
                    'severity': severity,
                    'vulnerability': vulnerability,
                    'url': message.get('url', ''),
                    'automation_decision': 'FILTERED',
                    'requires_manual_review': False
                }
                
                if self.producer:
                    self.producer.send('filtered-out-alerts', filtered_alert)
                
                logger.info(
                    f"❌ FILTERED: {vulnerability[:50]} "
                    f"(severity: {severity}) → filtered-out-alerts [{self.stats['filtered']}]"
                )
                return None
                
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return None
    
    def is_safe_low_severity(self, vulnerability):
        """Check if low-severity fix is safe to automate (UNIVERSAL)"""
        for safe_vuln in self.safe_low_severity:
            if safe_vuln.lower() in vulnerability.lower():
                return True
        return False
    
    def run(self):
        """Main loop with statistics"""
        logger.info(f"\n{'='*60}")
        logger.info(f"  {self.agent_name} STARTED - ENTERPRISE FILTERING")
        logger.info(f"{'='*60}")
        logger.info(f"Reading from: {self.input_topic}")
        logger.info(f"Writing to: {self.output_topic}")
        logger.info(f"Filtered to: filtered-out-alerts\n")
        logger.info("UNIVERSAL Filtering Rules:")
        logger.info("  ✅ High/Medium severity → unified-alerts")
        logger.info("  ✅ Low severity + safe config → unified-alerts")
        logger.info("  ❌ Low severity + risky → filtered-out-alerts\n")
        logger.info(f"{'='*60}\n")
        
        try:
            for kafka_message in self.consumer:
                message = kafka_message.value
                
                output = self.process_message(message)
                
                if output and self.producer:
                    self.producer.send(self.output_topic, output)
                    self.producer.flush(timeout=10)
                
                self.consumer.commit()
                
                if self.stats['total'] % 50 == 0:
                    total_forwarded = self.stats['high_medium'] + self.stats['safe_low']
                    automation_rate = (total_forwarded / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
                    
                    logger.info(
                        f"\n{'─'*60}"
                        f"\n📊 PROGRESS - Processed: {self.stats['total']}"
                        f"\n   High/Med: {self.stats['high_medium']} → unified-alerts"
                        f"\n   Safe-Low: {self.stats['safe_low']} → unified-alerts"
                        f"\n   Forwarded: {total_forwarded} ({automation_rate:.1f}%)"
                        f"\n   Filtered: {self.stats['filtered']} → filtered-out-alerts"
                        f"\n{'─'*60}\n"
                    )
                    
        except KeyboardInterrupt:
            logger.info(f"\n\n{'='*60}")
            logger.info(f"  {self.agent_name} STOPPING")
            logger.info(f"{'='*60}")
            self.print_final_stats()
        finally:
            self.cleanup()
    
    def print_final_stats(self):
        """Print final statistics"""
        total_forwarded = self.stats['high_medium'] + self.stats['safe_low']
        automation_rate = (total_forwarded / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
        
        logger.info(f"\n📊 FINAL STATISTICS:")
        logger.info(f"{'─'*60}")
        logger.info(f"Total Processed:        {self.stats['total']}")
        logger.info(f"  High/Medium Severity: {self.stats['high_medium']} → unified-alerts")
        logger.info(f"  Safe Low-Severity:    {self.stats['safe_low']} → unified-alerts")
        logger.info(f"  → Total Forwarded:    {total_forwarded} ({automation_rate:.1f}%)")
        logger.info(f"  → Filtered Out:       {self.stats['filtered']} → filtered-out-alerts")
        logger.info(f"{'─'*60}\n")
        logger.info(f"✅ Enterprise filtering optimized automation rate!")
        logger.info(f"✅ Filtered alerts available in 'filtered-out-alerts' topic")
        logger.info(f"{'='*60}\n")


if __name__ == "__main__":
    agent = WebMonitoringAgent()
    agent.run()