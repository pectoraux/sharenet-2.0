#!/bin/bash
# Start the two ShareNet node-link processes for the live mesh demo.
# Each is a real independent Bun process with its own port + keypair.
# Per spec/00 §37: "real independent processes, no simulator, no shared in-memory graph."

set -e
cd /home/z/my-project

# Kill any existing instances
pkill -f "bun.*mini-services/node-link/index.ts" 2>/dev/null || true
sleep 1

# Start Node A (control=3001, wire=7788)
nohup env NODE_NAME=node-a NODE_PORT=3001 WIRE_PORT=7788 \
  PERSIST_DIR=/home/z/my-project/mini-services/node-link/data/node-a \
  bun --hot mini-services/node-link/index.ts \
  > /tmp/node-a.log 2>&1 &
NODE_A_PID=$!
echo "Node A started (pid=$NODE_A_PID, control=3001, wire=7788)"

# Start Node B (control=3002, wire=7789)
nohup env NODE_NAME=node-b NODE_PORT=3002 WIRE_PORT=7789 \
  PERSIST_DIR=/home/z/my-project/mini-services/node-link/data/node-b \
  bun --hot mini-services/node-link/index.ts \
  > /tmp/node-b.log 2>&1 &
NODE_B_PID=$!
echo "Node B started (pid=$NODE_B_PID, control=3002, wire=7789)"

# Save PIDs for the stop script
echo "$NODE_A_PID" > /tmp/node-a.pid
echo "$NODE_B_PID" > /tmp/node-b.pid

# Wait for both to be ready
sleep 3

# Verify both are responding
A_OK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/status 2>/dev/null || echo "000")
B_OK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3002/status 2>/dev/null || echo "000")
echo "Node A status: HTTP $A_OK"
echo "Node B status: HTTP $B_OK"

if [ "$A_OK" = "200" ] && [ "$B_OK" = "200" ]; then
  echo "Both nodes ready."
  exit 0
else
  echo "ERROR: nodes not responding. Check /tmp/node-a.log and /tmp/node-b.log"
  exit 1
fi
