#!/bin/bash

echo "═══════════════════════════════════════════════════════════"
echo "         AEGENTRA - COMPLETE SYSTEM RESTART"
echo "═══════════════════════════════════════════════════════════"

cd ~/Aegentra1

# ════════════════════════════════════════════════════════════
# STEP 1: STOP ALL RUNNING AGENTS
# ════════════════════════════════════════════════════════════
echo ""
echo "1. STOPPING ALL RUNNING AGENTS..."
echo "   Press Ctrl+C to stop each agent, or wait for them to finish"
echo ""

# Kill any running Python agent processes
pkill -f "python.*monitoring_agent.py" 2>/dev/null
pkill -f "python.*correlation_agent.py" 2>/dev/null
pkill -f "python.*ai_analysis.py" 2>/dev/null
pkill -f "python.*ai_analysis_agent.py" 2>/dev/null
pkill -f "python.*universal_response_planning_agent.py" 2>/dev/null
pkill -f "python.*universal_policy_validation_agent.py" 2>/dev/null
pkill -f "python.*real_execution_agent.py" 2>/dev/null
pkill -f "python.*audit_agent.py" 2>/dev/null

echo "   ✅ All agents stopped"

# ════════════════════════════════════════════════════════════
# STEP 2: STOP AND RESTART KAFKA
# ════════════════════════════════════════════════════════════
echo ""
echo "2. RESTARTING KAFKA..."
echo ""

# Check if Kafka is running
if docker ps | grep -q kafka; then
    echo "   Stopping Kafka..."
    docker stop kafka
    docker rm kafka
    echo "   ✅ Kafka stopped"
else
    echo "   Kafka not running"
fi

# Start Kafka
echo "   Starting Kafka..."
docker run -d --name kafka \
    --network host \
    -e KAFKA_BROKER_ID=1 \
    -e KAFKA_ZOOKEEPER_CONNECT=localhost:2181 \
    -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
    -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:0:9092 \
    -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=true \
    confluentinc/cp-kafka:latest

echo "   Waiting for Kafka to start (30 seconds)..."
sleep 30

echo "   ✅ Kafka restarted"

# ════════════════════════════════════════════════════════════
# STEP 3: STOP AND RESTART ZAP
# ════════════════════════════════════════════════════════════
echo ""
echo "3. RESTARTING ZAP..."
echo ""

# Check if ZAP is running
if docker ps | grep -q zap; then
    echo "   Stopping ZAP..."
    docker stop zap
    docker rm zap
    echo "   ✅ ZAP stopped"
else
    echo "   ZAP not running"
fi

# Start ZAP
echo "   Starting ZAP..."
docker run -d --name zap --network host \
    ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true

echo "   Waiting for ZAP to start (60 seconds)..."
sleep 60

echo "   ✅ ZAP restarted"

# ════════════════════════════════════════════════════════════
# STEP 4: RESTART MINIMAL TEST APP WITH NGINX
# ════════════════════════════════════════════════════════════
echo ""
echo "4. RESTARTING MINIMAL TEST APP WITH NGINX..."
echo ""

# Check if minimal test app containers are running
if docker ps | grep -q aegentra-minimal; then
    echo "   Stopping minimal test app containers..."
    cd ~/Aegentra1/minimal-test-app
    docker-compose down
    echo "   ✅ Minimal test app stopped"
else
    echo "   Minimal test app not running"
fi

# Start minimal test app with Nginx
echo "   Starting minimal test app with Nginx..."
cd ~/Aegentra1/minimal-test-app
docker-compose up -d

echo "   Waiting for containers to start (10 seconds)..."
sleep 10

echo "   ✅ Minimal test app started"
echo "   Flask app: http://localhost:8086"
echo "   Nginx proxy: http://localhost:8087 (SCAN THIS PORT)"

# ════════════════════════════════════════════════════════════
# STEP 5: CHECK JUICE SHOP (OPTIONAL)
# ════════════════════════════════════════════════════════════
echo ""
echo "5. CHECKING JUICE SHOP (OPTIONAL)..."
echo ""

if docker ps | grep -q juice-shop; then
    echo "   ✅ Juice Shop is running on port 9090"
else
    echo "   Juice Shop not running"
    echo "   Starting Juice Shop..."
    docker run -d --name juice-shop -p 9090:3000 bkimminich/juice-shop
    echo "   Waiting for Juice Shop to start (10 seconds)..."
    sleep 10
    echo "   ✅ Juice Shop started"
fi

# ════════════════════════════════════════════════════════════
# STEP 6: PURGE KAFKA TOPICS (OPTIONAL)
# ════════════════════════════════════════════════════════════
echo ""
echo "6. PURGING KAFKA TOPICS (OPTIONAL)..."
echo ""
echo "   Topics to purge:"
echo "   - web-detection-alerts"
echo "   - unified-alerts"
echo "   - correlated-incidents"
echo "   - llm-analysis"
echo "   - response-plans"
echo "   - policy-decisions"
echo "   - executed-actions"
echo "   - audit-logs"
echo "   - filtered-out-alerts"
echo "   - held-for-review"
echo ""
read -p "   Purge all topics? (y/n): " purge_choice

if [ "$purge_choice" = "y" ]; then
    echo "   Purging topics..."
    ./purge_all_topics.sh
    echo "   ✅ Topics purged"
else
    echo "   Skipping topic purge"
fi

# ════════════════════════════════════════════════════════════
# STEP 7: START ALL AGENTS
# ════════════════════════════════════════════════════════════
echo ""
echo "7. STARTING ALL AGENTS..."
echo ""
echo "   Open 7 separate terminals and run the following commands:"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 1 - Monitoring Agent:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 agents/monitoring/monitoring_agent.py"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 2 - Correlation Agent:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 agents/correlation/correlation_agent.py"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 3 - AI Analysis Agent (Gemini 1.5 Flash):"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "export GEMINI_API_KEY='your-key-here'   # get free key from aistudio.google.com"
echo "source aegentra-env/bin/activate"
echo "python3 agents/analysis/ai_analysis_agent.py"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 4 - Response Planning Agent:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 agents/response/universal_response_planning_agent.py"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 5 - Policy Validation Agent:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 agents/policy_validation/universal_policy_validation_agent.py"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 6 - Execution Agent:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 agents/execution/real_execution_agent.py"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 7 - Audit Agent:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 agents/audit/audit_agent.py"
echo ""

# ════════════════════════════════════════════════════════════
# STEP 8: RUN ZAP SCANNER (OPTIONAL)
# ════════════════════════════════════════════════════════════
echo ""
echo "8. RUN ZAP SCANNER (OPTIONAL)..."
echo ""
echo "   Open TERMINAL 8 and run:"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "   TERMINAL 8 - ZAP Scanner:"
echo "═══════════════════════════════════════════════════════════"
echo "cd ~/Aegentra1"
echo "python3 detection/zap_scanner.py"
echo ""
echo "   IMPORTANT: Scanner will scan http://localhost:8087 (Nginx proxy)"
echo "   This allows AEGENTRA to patch the Nginx configuration!"
echo ""

# ════════════════════════════════════════════════════════════
# VERIFICATION
# ════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "         SYSTEM RESTART COMPLETE!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "VERIFICATION:"
echo "   Check if all services are running:"
echo "   - Kafka: docker ps | grep kafka"
echo "   - ZAP: docker ps | grep zap"
echo "   - Juice Shop: docker ps | grep juice-shop"
echo "   - Minimal Test App (Flask): docker ps | grep aegentra-minimal-flask"
echo "   - Minimal Test App (Nginx): docker ps | grep aegentra-minimal-nginx"
echo ""
echo "   Check if all agents are running:"
echo "   - ps aux | grep python.*agent"
echo ""
echo "   Check Kafka topics:"
echo "   - docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list"
echo ""
echo "   Test the minimal test app:"
echo "   - Flask app: http://localhost:8086"
echo "   - Nginx proxy: http://localhost:8087 (SCAN THIS PORT)"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""
