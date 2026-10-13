import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_agent import BaseAgent
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import yaml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CorrelationAgent(BaseAgent):
    """
    ENTERPRISE Correlation Agent: Groups related alerts into incidents
    FIXED: No hardcoding - reads from config.yaml
    """
    
    def __init__(self):
        super().__init__(
            agent_name="CorrelationAgent-Enterprise-v9",
            input_topic="unified-alerts",
            output_topic="correlated-incidents"
        )
        
        # Load configuration (NO MORE HARDCODING)
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Get correlation settings from config
        correlation_config = config.get('correlation', {})
        time_window_minutes = correlation_config.get('time_window_minutes', 5)
        self.group_threshold = correlation_config.get('group_threshold', 5)
        self.max_alerts = correlation_config.get('max_alerts_per_incident', 100)
        
        self.time_window = timedelta(minutes=time_window_minutes)
        self.alert_buffer = defaultdict(list)
        self.incident_count = 0
        
        logger.info(f"✅ Correlation settings loaded from config:")
        logger.info(f"   Time window: {time_window_minutes} minutes")
        logger.info(f"   Group threshold: {self.group_threshold} alerts")
        logger.info(f"   Max alerts per incident: {self.max_alerts}")
        
    def process_message(self, message):
        """
        UNIVERSAL correlation: Works for any vulnerability source
        """
        try:
            alert = message
            
            # Extract key for grouping (UNIVERSAL approach)
            source_ip = alert.get('source_ip', alert.get('url', 'unknown'))
            alert_type = alert.get('alert_type', 'web_vulnerability')
            timestamp_str = alert.get('timestamp', datetime.now().isoformat())
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except:
                timestamp = datetime.now()
            
            # Create grouping key: IP + Alert Type (UNIVERSAL)
            group_key = f"{source_ip}_{alert_type}"
            
            # Add to buffer
            self.alert_buffer[group_key].append({
                'alert': alert,
                'timestamp': timestamp
            })

            severity = alert.get('severity', 0)
            logger.info(f"Added alert to group {group_key}. Buffer size: {len(self.alert_buffer[group_key])}. Severity: {severity}")

            # High-severity alerts (ZAP High = 3) skip the threshold — they must reach execution
            if severity >= 3:
                logger.info(f"⚡ HIGH-SEVERITY alert (severity={severity}) — bypassing correlation threshold, creating incident immediately")
                incident = self.create_incident(group_key)
                return incident

            # Group when we reach threshold
            if len(self.alert_buffer[group_key]) >= self.group_threshold:
                incident = self.create_incident(group_key)
                return incident
            
            # Flush old groups periodically
            self.flush_old_groups()
            
            return None
            
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_incident(self, group_key):
        """Create incident from grouped alerts (UNIVERSAL)"""
        alerts = self.alert_buffer[group_key]
        
        if not alerts:
            return None
        
        # Limit alerts per incident
        if len(alerts) > self.max_alerts:
            logger.warning(f"Group {group_key} has {len(alerts)} alerts, limiting to {self.max_alerts}")
            alerts = alerts[:self.max_alerts]
        
        alerts.sort(key=lambda x: x['timestamp'])
        
        self.incident_count += 1
        
        incident = {
            'incident_id': f"INC-{int(datetime.now().timestamp())}-{self.incident_count}",
            'created_at': datetime.now().isoformat(),
            'group_key': group_key,
            'alert_count': len(alerts),
            'first_seen': alerts[0]['timestamp'].isoformat(),
            'last_seen': alerts[-1]['timestamp'].isoformat(),
            'source_ip': alerts[0]['alert'].get('source_ip', alerts[0]['alert'].get('url', 'unknown')),
            'alert_type': alerts[0]['alert'].get('alert_type', 'web_vulnerability'),
            'alerts': [a['alert'] for a in alerts],
            'severity': max([a['alert'].get('severity', 0) for a in alerts]),
            'summary': f"{len(alerts)} related alerts from {group_key}"
        }
        
        logger.info(f"✅ Created incident {incident['incident_id']} with {len(alerts)} alerts")
        
        if self.producer:
            self.producer.send(self.output_topic, incident)
            self.producer.flush(timeout=10)
        
        self.alert_buffer[group_key] = []
        
        return incident
    
    def flush_old_groups(self):
        """Flush groups that have been waiting too long"""
        now = datetime.now()
        
        for group_key in list(self.alert_buffer.keys()):
            alerts = self.alert_buffer[group_key]
            
            if not alerts:
                continue
            
            oldest = min([a['timestamp'] for a in alerts])
            if now - oldest > self.time_window:
                if len(alerts) > 0:
                    self.create_incident(group_key)
    
    def cleanup(self):
        """Flush all remaining groups on shutdown"""
        logger.info("Flushing all remaining groups...")
        
        total_flushed = 0
        for group_key in list(self.alert_buffer.keys()):
            if len(self.alert_buffer[group_key]) > 0:
                incident = self.create_incident(group_key)
                if incident:
                    total_flushed += 1
        
        logger.info(f"Flushed {total_flushed} remaining incidents")
        logger.info(f"Total incidents created: {self.incident_count}")
        
        super().cleanup()


if __name__ == "__main__":
    agent = CorrelationAgent()
    agent.run()