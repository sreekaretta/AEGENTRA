#!/usr/bin/env python3
import json
from kafka import KafkaConsumer

print("Reading alerts from Kafka topic 'web-detection-alerts'...")

consumer = KafkaConsumer(
    'web-detection-alerts',
    bootstrap_servers='localhost:9092',
    auto_offset_reset='earliest',
    consumer_timeout_ms=5000,
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

alerts = []
for msg in consumer:
    alerts.append(msg.value)

consumer.close()

# Save detailed JSON
with open('/tmp/scan1_alerts.json', 'w') as f:
    json.dump(alerts, f, indent=2)

# Save summary by type
summary = {}
for alert in alerts:
    key = alert.get('alert', 'Unknown')
    summary[key] = summary.get(key, 0) + 1

with open('/tmp/scan1_summary.txt', 'w') as f:
    f.write(f"SCAN 1 (BEFORE PATCHES): {len(alerts)} total vulnerabilities\n")
    f.write("=" * 80 + "\n")
    for vuln, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
        f.write(f"{count:3d}x  {vuln}\n")

print(f"\n✅ Saved {len(alerts)} alerts to /tmp/scan1_alerts.json")
print(f"✅ Summary saved to /tmp/scan1_summary.txt")
print("\nScan 1 Summary:")
print("=" * 80)
for vuln, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
    print(f"{count:3d}x  {vuln}")
print("=" * 80)
