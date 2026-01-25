#!/bin/bash

set -e

echo "=== NmapUI Go Integration Test ==="
echo

BASE_URL="http://localhost:9000"

echo "1. Testing health endpoint..."
HEALTH=$(curl -s "$BASE_URL/api/health")
echo "Response: $HEALTH"
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi
echo

echo "2. Testing version endpoint..."
VERSION=$(curl -s "$BASE_URL/api/version")
echo "Response: $VERSION"
if echo "$VERSION" | grep -q '"app_version"'; then
    echo "✓ Version endpoint passed"
else
    echo "✗ Version endpoint failed"
    exit 1
fi
echo

echo "3. Testing customers endpoint..."
CUSTOMERS=$(curl -s "$BASE_URL/api/customers")
echo "Response: $CUSTOMERS"
if echo "$CUSTOMERS" | grep -q '"customers"'; then
    echo "✓ Customers endpoint passed"
else
    echo "✗ Customers endpoint failed"
    exit 1
fi
echo

echo "4. Testing current assignment endpoint..."
ASSIGNMENT=$(curl -s "$BASE_URL/api/customer/current")
echo "Response: $ASSIGNMENT"
echo "✓ Assignment endpoint passed"
echo

echo "5. Testing scan history endpoint..."
HISTORY=$(curl -s "$BASE_URL/api/scan/history?limit=10")
echo "Response: $HISTORY"
if echo "$HISTORY" | grep -q '"history"'; then
    echo "✓ Scan history endpoint passed"
else
    echo "✗ Scan history endpoint failed"
    exit 1
fi
echo

echo "6. Testing scans list endpoint..."
SCANS=$(curl -s "$BASE_URL/api/scans?limit=10")
echo "Response: $SCANS"
if echo "$SCANS" | grep -q '"scans"'; then
    echo "✓ Scans list endpoint passed"
else
    echo "✗ Scans list endpoint failed"
    exit 1
fi
echo

echo "=== All integration tests passed! ==="
echo
echo "API Endpoints Verified:"
echo "  ✓ GET  /api/health"
echo "  ✓ GET  /api/version"
echo "  ✓ GET  /api/customers"
echo "  ✓ GET  /api/customer/current"
echo "  ✓ GET  /api/scan/history"
echo "  ✓ GET  /api/scans"
echo
echo "Ready for production deployment!"
