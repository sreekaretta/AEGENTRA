from kafka.admin import KafkaAdminClient, NewTopic

def create_topics():
    admin_client = KafkaAdminClient(
        bootstrap_servers='localhost:9092',
        client_id='aegentra-admin'
    )
    
    # Define all topics for enterprise architecture
    topics = [
        # Detection-specific topics (separate by source)
        NewTopic(name='network-detection-alerts', num_partitions=3, replication_factor=1),
        NewTopic(name='web-detection-alerts', num_partitions=3, replication_factor=1),
        NewTopic(name='malware-detection-alerts', num_partitions=3, replication_factor=1),
        
        # Unified alerts (all sources combined after filtering)
        NewTopic(name='unified-alerts', num_partitions=3, replication_factor=1),
        
        # Processing pipeline topics
        NewTopic(name='correlated-incidents', num_partitions=2, replication_factor=1),
        NewTopic(name='llm-analysis', num_partitions=2, replication_factor=1),
        NewTopic(name='response-plans', num_partitions=2, replication_factor=1),
        NewTopic(name='policy-decisions', num_partitions=2, replication_factor=1),
        NewTopic(name='executed-actions', num_partitions=1, replication_factor=1),
        NewTopic(name='audit-logs', num_partitions=1, replication_factor=1),
        
        # Legacy topic (for old data, can delete later)
        # NewTopic(name='detection-alerts', num_partitions=3, replication_factor=1),
    ]
    
    try:
        admin_client.create_topics(new_topics=topics, validate_only=False)
        print("✅ Topics created successfully!")
        print("\nCreated topics:")
        for topic in topics:
            print(f"  - {topic.name}")
    except Exception as e:
        print(f"Note: {e}")
        print("(Topics may already exist, which is fine)")
    
    finally:
        admin_client.close()

if __name__ == "__main__":
    create_topics()