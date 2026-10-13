#!/bin/bash
pkill -f "python.*monitoring_agent.py" 2>/dev/null
pkill -f "python.*correlation_agent.py" 2>/dev/null
pkill -f "python.*ai_analysis_agent.py" 2>/dev/null
pkill -f "python.*ai_analysis.py" 2>/dev/null
pkill -f "python.*universal_response_planning_agent.py" 2>/dev/null
pkill -f "python.*universal_policy_validation_agent.py" 2>/dev/null
pkill -f "python.*real_execution_agent.py" 2>/dev/null
pkill -f "python.*audit_agent.py" 2>/dev/null
pkill -f "python.*zap_scanner.py" 2>/dev/null
echo "✅ All agents stopped"
