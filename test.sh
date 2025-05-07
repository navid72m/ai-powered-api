#!/bin/bash
# test-consolidated.sh - Test script for the consolidated AI-Powered API Gateway

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# API Gateway URL
GATEWAY_URL="http://localhost:8080"
AUTH_TOKEN="test-token"

echo -e "${YELLOW}Testing AI-Powered API Gateway (Consolidated Version)${NC}"
echo "============================================================="

# Check if API Gateway is running
echo -e "\n${YELLOW}Checking if API Gateway is running...${NC}"
health_response=$(curl -s -o /dev/null -w "%{http_code}" $GATEWAY_URL/health)
if [ "$health_response" == "200" ]; then
    echo -e "${GREEN}API Gateway is running!${NC}"
else
    echo -e "${RED}Error: API Gateway is not running. Please start it first.${NC}"
    exit 1
fi

# Function to make API requests
make_request() {
    local endpoint=$1
    local method=${2:-GET}
    local data=${3:-""}
    local content_type=${4:-"application/json"}
    
    echo -e "\n${YELLOW}Making $method request to $endpoint${NC}"
    if [ ! -z "$data" ]; then
        echo "Payload: $data"
    fi
    
    if [ "$method" == "GET" ]; then
        response=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" $GATEWAY_URL$endpoint)
    else
        response=$(curl -s -X $method \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "Content-Type: $content_type" \
            -d "$data" \
            $GATEWAY_URL$endpoint)
    fi
    
    # Check if response is valid JSON and pretty-print if it is
    echo "Response:"
    if echo "$response" | jq . > /dev/null 2>&1; then
        echo "$response" | jq .
    else
        echo "$response"
    fi
}

# Test 1: Health Check
echo -e "\n${YELLOW}Test 1: Health Check${NC}"
make_request "/health"

# Test 2: Dashboard
echo -e "\n${YELLOW}Test 2: Dashboard${NC}"
make_request "/dashboard"

# Test 3: Standard API Request
echo -e "\n${YELLOW}Test 3: Standard API Request${NC}"
make_request "/api/mock/users"

# Test 4: Admin API Request
echo -e "\n${YELLOW}Test 4: Admin API Request${NC}"
make_request "/api/mock/admin/settings"

# Test 5: Analytics API Request
echo -e "\n${YELLOW}Test 5: Analytics API Request${NC}"
make_request "/api/mock/analytics/metrics"

# Test 6: Report API Request
echo -e "\n${YELLOW}Test 6: Report API Request${NC}"
make_request "/api/mock/reports/monthly"

# Test 7: POST Request with JSON Body
echo -e "\n${YELLOW}Test 7: POST Request with JSON Body${NC}"
make_request "/api/mock/users" "POST" '{"name":"John Doe","email":"john@example.com"}'

# Test 8: Potentially Risky Request
echo -e "\n${YELLOW}Test 8: Potentially Risky Request${NC}"
make_request "/api/mock/admin/users/delete" "DELETE" '{"confirm":true}'

# Test 9: Non-existent Route
echo -e "\n${YELLOW}Test 9: Non-existent Route${NC}"
make_request "/not-found"

# Test 10: Rate Limiting
echo -e "\n${YELLOW}Test 10: Rate Limiting (sending multiple admin requests)${NC}"
for i in {1..7}; do
    echo "Request $i:"
    response=$(curl -s -w "\nStatus: %{http_code}" -H "Authorization: Bearer $AUTH_TOKEN" $GATEWAY_URL/api/mock/admin/settings)
    echo "$response"
    
    status_code=$(echo "$response" | grep "Status:" | awk '{print $2}')
    if [ "$status_code" == "429" ]; then
        echo -e "${GREEN}Rate limiting working! Request blocked after $i requests.${NC}"
        break
    fi
    
    # Short delay between requests
    sleep 0.5
done

# Final Dashboard Check
echo -e "\n${YELLOW}Final Dashboard Check:${NC}"
make_request "/dashboard"

echo -e "\n${GREEN}Testing complete!${NC}"