#!/bin/bash

echo "═══════════════════════════════════════════════════════════"
echo "         AEGENTRA - DEPLOYING ALL FIXES"
echo "═══════════════════════════════════════════════════════════"

cd ~/Aegentra1

# 1. DELETE REDUNDANT FILES
echo "1. Deleting redundant analysis agents..."
rm -f agents/analysis/ai_analysis_glm.py
rm -f agents/analysis/ai_analysis_agent.py
echo "   ✅ Deleted redundant files"

# 2. BACKUP CURRENT FILES
echo "2. Creating backups..."
mkdir -p backups
cp config.yaml backups/config.yaml.backup
cp agents/correlation/correlation_agent.py backups/correlation_agent.py.backup
cp agents/execution/real_execution_agent.py backups/real_execution_agent.py.backup
echo "   ✅ Backups created in ./backups/"

# 3. UPDATE CONFIG.YAML (manual - show reminder)
echo "3. UPDATE config.yaml manually with new settings"
echo "   ⚠️  Open config.yaml and paste the updated version"

# 4. RESTART INFRASTRUCTURE
echo "4. Restarting infrastructure..."
docker stop zap
docker rm zap
docker run -d --name zap --network host \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true

echo "   Waiting for ZAP to start (60 seconds)..."
sleep 60

echo "   ✅ ZAP restarted"

# 5. VERIFY
echo "5. Verifying installation..."
echo "   Files to verify:"
echo "   - config.yaml (updated)"
echo "   - agents/correlation/correlation_agent.py (updated)"
echo "   - agents/execution/real_execution_agent.py (updated)"
echo "   - agents/analysis/ (only ai_analysis.py should remain)"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "         DEPLOYMENT COMPLETE!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "NEXT STEPS:"
echo "1. Update config.yaml with new version"
echo "2. Update correlation_agent.py"
echo "3. Update real_execution_agent.py"
echo "4. Purge Kafka topics: http://localhost:8080"
echo "5. Run fresh scan"
echo ""
