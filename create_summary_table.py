#!/usr/bin/env python3
"""
Summary Table Generator
Creates clean Excel/CSV summary of entire pipeline
"""

from kafka import KafkaConsumer
import json
import pandas as pd
from datetime import datetime
import os

print("="*60)
print("AEGENTRA - Summary Table Generator")
print("="*60)

# Kafka connection
bootstrap_servers = ['localhost:9092']

# Read all topics
topics = {
    'web-detection-alerts': [],
    'unified-alerts': [],
    'correlated-incidents': [],
    'llm-analysis': [],
    'response-plans': [],
    'policy-decisions': [],
    'executed-actions': [],
    'audit-logs': []
}

print("\nReading Kafka topics...")

for topic_name in topics.keys():
    try:
        consumer = KafkaConsumer(
            topic_name,
            bootstrap_servers=bootstrap_servers,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='earliest',
            enable_auto_commit=False,
            consumer_timeout_ms=5000
        )
        
        messages = []
        for message in consumer:
            messages.append(message.value)
        
        topics[topic_name] = messages
        consumer.close()
        print(f"  ✅ {topic_name}: {len(messages)} messages")
    except Exception as e:
        print(f"  ❌ {topic_name}: {e}")

# Create summary table
summary_rows = []

print("\nGenerating summary table...")

# Process executed actions
for execution in topics['executed-actions']:
    incident_id = execution.get('incident_id')
    
    # Find corresponding analysis
    analysis = None
    for a in topics['llm-analysis']:
        if a.get('incident_id') == incident_id:
            analysis = a
            break
    
    # Find corresponding plan
    plan = None
    for p in topics['response-plans']:
        if p.get('incident_id') == incident_id:
            plan = p
            break
    
    # Find corresponding decision
    decision = None
    for d in topics['policy-decisions']:
        if d.get('plan_id') == execution.get('plan_id'):
            decision = d
            break
    
    # Create row
    row = {
        'Incident ID': incident_id,
        'Execution ID': execution.get('execution_id'),
        'Executed At': execution.get('executed_at'),
        'Threat Type': analysis.get('threat_type', 'Unknown') if analysis else 'Unknown',
        'Severity': analysis.get('severity', 0) if analysis else 0,
        'Confidence': analysis.get('confidence', 0) if analysis else 0,
        'MITRE Technique': analysis.get('mitre_technique', '') if analysis else '',
        'MITRE Tactic': analysis.get('mitre_tactic', '') if analysis else '',
        'Actions Total': execution.get('actions_total', 0),
        'Actions Successful': execution.get('actions_successful', 0),
        'Actions Failed': execution.get('actions_failed', 0),
        'Overall Status': execution.get('overall_status'),
        'Decision': decision.get('decision', 'Unknown') if decision else 'Unknown',
        'Tech Stack': f"{plan.get('tech_stack', {}).get('web_server', 'unknown')}/{plan.get('tech_stack', {}).get('language', 'unknown')}" if plan else 'unknown',
        'Automation Approved': execution.get('automation_approved', False),
        'Real Execution': execution.get('real_execution', False)
    }
    
    summary_rows.append(row)

# Create DataFrame
df = pd.DataFrame(summary_rows)

# Sort by execution time
df = df.sort_values('Executed At', ascending=False)

# Save to Excel
output_file = '/tmp/aegentra_summary.xlsx'
df.to_excel(output_file, index=False, sheet_name='Execution Summary')

print(f"\n✅ Summary table created: {output_file}")
print(f"\n📊 Summary Statistics:")
print(f"  Total Executions: {len(df)}")
print(f"  Successful: {len(df[df['Overall Status'] == 'SUCCESS'])}")
print(f"  Partial: {len(df[df['Overall Status'] == 'PARTIAL'])}")
print(f"  Total Actions: {df['Actions Total'].sum()}")
print(f"  Successful Actions: {df['Actions Successful'].sum()}")
print(f"  Failed Actions: {df['Actions Failed'].sum()}")
print(f"  Success Rate: {(df['Actions Successful'].sum() / df['Actions Total'].sum() * 100):.1f}%")

# Save to CSV as well
csv_file = '/tmp/aegentra_summary.csv'
df.to_csv(csv_file, index=False)
print(f"\n✅ CSV file created: {csv_file}")

# Display preview
print("\n📋 Preview (First 5 rows):")
print(df.head().to_string())

print("\n" + "="*60)
print("SUMMARY TABLE GENERATION COMPLETE!")
print("="*60)
print(f"\nFiles created:")
print(f"  Excel: {output_file}")
print(f"  CSV: {csv_file}")
print("\nDownload these files to view complete summary!")
