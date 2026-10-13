#!/bin/bash
# Start all AEGENTRA agents in the background — single terminal
# Usage: export GEMINI_API_KEY='your-key' && bash start_agents.sh

cd ~/Aegentra1
source aegentra-env/bin/activate
mkdir -p logs

echo "═══════════════════════════════════════════════════════════"
echo "         AEGENTRA — Starting All Agents"
echo "═══════════════════════════════════════════════════════════"

# Wait for Kafka
echo "Waiting for Kafka to be ready..."
for i in $(seq 1 30); do
    if docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
        echo "✅ Kafka is ready"
        break
    fi
    echo "  Kafka not ready yet ($i/30)..."
    sleep 3
done

# Kill any existing agents
pkill -f "python.*monitoring_agent.py" 2>/dev/null
pkill -f "python.*correlation_agent.py" 2>/dev/null
pkill -f "python.*ai_analysis_agent.py" 2>/dev/null
pkill -f "python.*ai_analysis.py" 2>/dev/null
pkill -f "python.*universal_response_planning_agent.py" 2>/dev/null
pkill -f "python.*universal_policy_validation_agent.py" 2>/dev/null
pkill -f "python.*real_execution_agent.py" 2>/dev/null
pkill -f "python.*audit_agent.py" 2>/dev/null
sleep 2

echo ""
echo "Starting agents..."

# 1. Monitoring Agent
python3 agents/monitoring/monitoring_agent.py > logs/monitoring.log 2>&1 &
echo "✅ Monitoring Agent     (PID $!) → logs/monitoring.log"

sleep 2

# 2. Correlation Agent
python3 agents/correlation/correlation_agent.py > logs/correlation.log 2>&1 &
echo "✅ Correlation Agent    (PID $!) → logs/correlation.log"

sleep 2

# 3. AI Analysis Agent (Gemini) — reads GEMINI_API_KEY from env
if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️  GEMINI_API_KEY not set — AI agent will use keyword fallback"
fi
python3 agents/analysis/ai_analysis_agent.py > logs/analysis.log 2>&1 &
echo "✅ AI Analysis Agent    (PID $!) → logs/analysis.log"

sleep 2

# 4. Response Planning Agent
python3 agents/response/universal_response_planning_agent.py > logs/response.log 2>&1 &
echo "✅ Response Agent       (PID $!) → logs/response.log"

sleep 2

# 5. Policy Validation Agent
python3 agents/policy_validation/universal_policy_validation_agent.py > logs/policy.log 2>&1 &
echo "✅ Policy Agent         (PID $!) → logs/policy.log"

sleep 2

# 6. Execution Agent
python3 agents/execution/real_execution_agent.py > logs/execution.log 2>&1 &
echo "✅ Execution Agent      (PID $!) → logs/execution.log"

sleep 2

# 7. Audit Agent
python3 agents/audit/audit_agent.py > logs/audit.log 2>&1 &
echo "✅ Audit Agent          (PID $!) → logs/audit.log"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "All agents started. Logs in ~/Aegentra1/logs/"
echo ""
echo "Run scanner: python3 detection/zap_scanner.py"
echo "Watch logs:  tail -f logs/execution.log logs/analysis.log"
echo "Stop all:    bash stop_agents.sh"
echo "═══════════════════════════════════════════════════════════"
