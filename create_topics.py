from kafka.admin import KafkaAdminClient, NewTopic

admin = KafkaAdminClient(bootstrap_servers=['localhost:9092'])

topics = [
    NewTopic(name='web-detection-alerts', num_partitions=3, replication_factor=1),
    NewTopic(name='unified-alerts', num_partitions=3, replication_factor=1),
    NewTopic(name='correlated-incidents', num_partitions=2, replication_factor=1),
    NewTopic(name='llm-analysis', num_partitions=2, replication_factor=1),
    NewTopic(name='audit-logs', num_partitions=1, replication_factor=1),
    NewTopic(name='detection-alerts', num_partitions=3, replication_factor=1),
    NewTopic(name='malware-detection-alerts', num_partitions=3, replication_factor=1),
    NewTopic(name='network-detection-alerts', num_partitions=3, replication_factor=1),
    NewTopic(name='raw-events', num_partitions=3, replication_factor=1)
]

try:
    admin.create_topics(new_topics=topics, validate_only=False)
    print("✅ All topics created!")
except Exception as e:
    print(f"Topics created (some may already exist): {e}")

admin.close()
