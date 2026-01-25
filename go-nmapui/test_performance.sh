#!/bin/bash
# Performance and load testing for NmapUI Go Edition

set -e

SERVER_URL="http://localhost:9000"
RESULTS_FILE="performance_results.txt"

echo "=============================================="
echo "NmapUI Go Edition - Performance Tests"
echo "=============================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if server is running
echo -n "Checking if server is running... "
if ! curl -s -f "${SERVER_URL}/api/health" > /dev/null 2>&1; then
    echo -e "${RED}FAILED${NC}"
    echo "Server is not running at ${SERVER_URL}"
    echo "Start the server with: ./bin/nmapui"
    exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# Clear results file
> "$RESULTS_FILE"

# Test 1: API endpoint response times
echo "=== Test 1: API Endpoint Response Times ==="
echo "Testing response times for all endpoints..."
echo ""
echo "API Endpoint Response Times" >> "$RESULTS_FILE"
echo "===========================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

endpoints=(
    "GET /api/health"
    "GET /api/version"
    "GET /api/customers"
    "GET /api/customer/current"
    "GET /api/scan/history"
    "GET /api/scans"
    "GET /api/network/key"
)

for endpoint in "${endpoints[@]}"; do
    method=$(echo "$endpoint" | awk '{print $1}')
    path=$(echo "$endpoint" | awk '{print $2}')
    
    echo -n "  $endpoint ... "
    
    # Measure time with curl
    response_time=$(curl -s -w "%{time_total}" -o /dev/null "${SERVER_URL}${path}")
    
    # Convert to milliseconds
    response_time_ms=$(echo "$response_time * 1000" | bc)
    
    echo -e "${GREEN}${response_time_ms}ms${NC}"
    echo "$endpoint: ${response_time_ms}ms" >> "$RESULTS_FILE"
done

echo ""
echo "" >> "$RESULTS_FILE"

# Test 2: Concurrent quick scans
echo "=== Test 2: Concurrent Quick Scans ==="
echo "Running 5 quick scans in parallel..."
echo ""
echo "Concurrent Quick Scans" >> "$RESULTS_FILE"
echo "======================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

START_TIME=$(date +%s)

for i in {1..5}; do
    (
        target="127.0.0.$i"
        start=$(date +%s.%N)
        curl -s -X POST "${SERVER_URL}/api/scan/quick" \
            -H "Content-Type: application/json" \
            -d "{\"target\":\"${target}\",\"timing\":\"T3\"}" > /dev/null
        end=$(date +%s.%N)
        duration=$(echo "$end - $start" | bc)
        duration_ms=$(echo "$duration * 1000" | bc)
        echo "  Scan ${i} (${target}): ${duration_ms}ms"
        echo "Scan ${i} (${target}): ${duration_ms}ms" >> "$RESULTS_FILE"
    ) &
done

wait

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo -e "${GREEN}All scans completed in ${TOTAL_TIME}s${NC}"
echo "Total time: ${TOTAL_TIME}s" >> "$RESULTS_FILE"
echo ""
echo "" >> "$RESULTS_FILE"

# Test 3: Memory usage
echo "=== Test 3: Memory Usage ==="
echo "Checking server process memory usage..."
echo ""
echo "Memory Usage" >> "$RESULTS_FILE"
echo "============" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Get PID of nmapui process
PID=$(pgrep -f "nmapui" | head -1)

if [ -z "$PID" ]; then
    echo -e "${YELLOW}Could not find nmapui process${NC}"
    echo "Could not find nmapui process" >> "$RESULTS_FILE"
else
    # Get memory usage (macOS compatible)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        MEM_KB=$(ps -o rss= -p "$PID")
        MEM_MB=$(echo "scale=2; $MEM_KB / 1024" | bc)
    else
        MEM_KB=$(ps -o rss= -p "$PID")
        MEM_MB=$(echo "scale=2; $MEM_KB / 1024" | bc)
    fi
    
    echo -e "  Process ID: ${GREEN}${PID}${NC}"
    echo -e "  Memory: ${GREEN}${MEM_MB} MB${NC}"
    
    echo "Process ID: ${PID}" >> "$RESULTS_FILE"
    echo "Memory: ${MEM_MB} MB" >> "$RESULTS_FILE"
fi

echo ""
echo "" >> "$RESULTS_FILE"

# Test 4: Database query performance
echo "=== Test 4: Database Query Performance ==="
echo "Testing scan history retrieval speed..."
echo ""
echo "Database Query Performance" >> "$RESULTS_FILE"
echo "==========================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

for limit in 10 50 100; do
    echo -n "  Fetching $limit scan records... "
    
    start=$(date +%s.%N)
    curl -s "${SERVER_URL}/api/scan/history?limit=${limit}" > /dev/null
    end=$(date +%s.%N)
    
    duration=$(echo "$end - $start" | bc)
    duration_ms=$(echo "$duration * 1000" | bc)
    
    echo -e "${GREEN}${duration_ms}ms${NC}"
    echo "Limit $limit: ${duration_ms}ms" >> "$RESULTS_FILE"
done

echo ""
echo "" >> "$RESULTS_FILE"

# Test 5: WebSocket connection stress test
echo "=== Test 5: WebSocket Connection Test ==="
echo "Testing WebSocket connection stability..."
echo ""
echo "WebSocket Connection Test" >> "$RESULTS_FILE"
echo "==========================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Create temporary WebSocket test script
cat > /tmp/ws_test.js << 'EOF'
const WebSocket = require('ws');
const ws = new WebSocket('ws://localhost:9000/ws');

let connected = false;
let messageCount = 0;

ws.on('open', () => {
    connected = true;
    console.log('WebSocket connected');
    
    // Send ping every 100ms for 5 seconds
    const interval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ event: 'ping', data: { timestamp: Date.now() } }));
        } else {
            clearInterval(interval);
        }
    }, 100);
    
    setTimeout(() => {
        clearInterval(interval);
        console.log('Messages sent: ~50');
        console.log('Messages received: ' + messageCount);
        ws.close();
    }, 5000);
});

ws.on('message', (data) => {
    messageCount++;
});

ws.on('close', () => {
    if (connected) {
        console.log('WebSocket closed cleanly');
        process.exit(0);
    } else {
        console.log('WebSocket connection failed');
        process.exit(1);
    }
});

ws.on('error', (error) => {
    console.error('WebSocket error:', error.message);
    process.exit(1);
});
EOF

if command -v node &> /dev/null; then
    echo -n "  Running WebSocket stress test... "
    
    if node /tmp/ws_test.js > /tmp/ws_output.txt 2>&1; then
        cat /tmp/ws_output.txt
        cat /tmp/ws_output.txt >> "$RESULTS_FILE"
        echo -e "${GREEN}PASSED${NC}"
        echo "Status: PASSED" >> "$RESULTS_FILE"
    else
        echo -e "${RED}FAILED${NC}"
        cat /tmp/ws_output.txt
        echo "Status: FAILED" >> "$RESULTS_FILE"
    fi
    
    rm /tmp/ws_test.js /tmp/ws_output.txt
else
    echo -e "${YELLOW}Node.js not found, skipping WebSocket test${NC}"
    echo "Node.js not found, skipping WebSocket test" >> "$RESULTS_FILE"
fi

echo ""
echo "" >> "$RESULTS_FILE"

# Final summary
echo "=============================================="
echo "Performance Test Complete"
echo "=============================================="
echo ""
echo "Results saved to: $RESULTS_FILE"
echo ""
echo -e "${GREEN}All tests completed successfully!${NC}"
echo ""

# Display results file
echo "=== Full Results ==="
cat "$RESULTS_FILE"
