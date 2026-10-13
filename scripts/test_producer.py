#!/usr/bin/env python3
"""
Test Producer - Sends test alerts to Kafka
"""
import json
import time
from kafka import KafkaProducer
from datetime import datetime

# Kafka configuration
KAFKA_SERVERS = ['localhost:9092']
TOPIC = 'detection-alerts'

def create_test_alert(alert_id, source_ip, attack_type, severity):
    """Create a test alert"""
    return {
        'alert_id': alert_id,
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': source_ip,
        'destination_ip': '10.0.0.10',
        'source_port': 12345,
        'destination_port': 22,
        'protocol': 'TCP',
        'alert_type': 'suricata',
        'signature': f'ET SCAN {attack_type}',
        'severity': severity,
        'raw_data': {
            'description': f'Test {attack_type} from {source_ip}'
        }
    }

def main():
    print(f"Connecting to Kafka at {KAFKA_SERVERS}...")
    
    # Create producer
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    
    print(f"✓ Connected! Sending test alerts to '{TOPIC}'...\n")
    
    # Send 5 test alerts
    test_alerts = [
        ('ALR-001', '192.168.1.50', 'Port Scan', 2),
        ('ALR-002', '192.168.1.50', 'SSH Brute Force', 3),
        ('ALR-003', '10.0.0.99', 'Malware C2 Communication', 3),
        ('ALR-004', '192.168.1.75', 'SQL Injection Attempt', 3),
        ('ALR-005', '192.168.1.50', 'Privilege Escalation', 3),
    ]
    
    for alert_id, source_ip, attack_type, severity in test_alerts:
        alert = create_test_alert(alert_id, source_ip, attack_type, severity)
        
        # Send to Kafka with source IP as key (for partitioning)
        producer.send(
            TOPIC,
            key=source_ip.encode('utf-8'),
            value=alert
        )
        
        print(f"✓ Sent: {alert_id} - {attack_type} from {source_ip}")
        time.sleep(1)  # Wait 1 second between alerts
    
    # Flush and close
    producer.flush()
    producer.close()
    
    print(f"\n✓ Sent {len(test_alerts)} test alerts successfully!")

if __name__ == '__main__':
    main()