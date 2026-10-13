#!/bin/bash

# Purge all AEGENTRA topics for fresh start

KAFKA_CONTAINER=$(docker ps --filter "name=kafka" --format "{{.Names}}" | head -1)

if [ -z "$KAFKA_CONTAINER" ]; then
    echo "❌ Kafka container not found!"
    exit 1
fi

echo "🧹 Purging all AEGENTRA topics..."

TOPICS=(
    "web-detection-alerts"
    "unified-alerts"
    "correlated-incidents"
    "llm-analysis"
    "response-plans"
    "policy-decisions"
    "executed-actions"
    "audit-logs"
)

for topic in "${TOPICS[@]}"; do
    echo "  Deleting and recreating: $topic"
    
    # Delete topic
    docker exec $KAFKA_CONTAINER kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --delete --topic $topic 2>/dev/null
    
    sleep 1
    
    # Recreate topic
    docker exec $KAFKA_CONTAINER kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create --topic $topic \
        --partitions 3 \
        --replication-factor 1 2>/dev/null
    
    echo "  ✅ $topic purged"
done

echo ""
echo "🎉 All topics purged! Ready for fresh DVWA scan!"
echo ""
echo "Next steps:"
echo "  1. Scan DVWA: python scanners/zap_scanner.py"
echo "  2. Check topics: http://localhost:8080"
