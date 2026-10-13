from kafka.admin import KafkaAdminClient, NewTopic

admin = KafkaAdminClient(bootstrap_servers=['localhost:9092'])

topics = [
    NewTopic(name='filtered-out-alerts', num_partitions=3, replication_factor=1),
    NewTopic(name='held-for-review', num_partitions=2, replication_factor=1)
]

try:
    admin.create_topics(new_topics=topics, validate_only=False)
    print("✅ Filtered topics created!")
    print("  - filtered-out-alerts (for monitoring agent)")
    print("  - held-for-review (for execution agent)")
except Exception as e:
    print(f"Topics may already exist: {e}")

admin.close()