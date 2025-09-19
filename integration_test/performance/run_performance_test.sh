#!/bin/bash
#
# Wrapper script for running MCP server performance tests with common scenarios.
#

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default values
URL="http://localhost:8000/mcp"
AUTH_TYPE="bearer"
TOKEN=""

print_usage() {
    echo "Usage: $0 [OPTIONS] --token TOKEN"
    echo ""
    echo "Options:"
    echo "  --token TOKEN        Authentication token (required)"
    echo "  --url URL           MCP server URL (default: $URL)"
    echo "  --auth-type TYPE    Auth type: bearer or offline-token (default: $AUTH_TYPE)"
    echo "  --scenario SCENARIO  Test scenario (light, moderate, heavy, stress)"
    echo "  --help              Show this help message"
    echo ""
    echo "Note: Test results will be automatically saved to a JSON file."
    echo ""
    echo "Test Scenarios:"
    echo "  light      - 5 users, 3 requests each (15 total requests)"
    echo "  moderate   - 20 users, 5 requests each (100 total requests)"
    echo "  heavy      - 50 users, 10 requests each (500 total requests)"
    echo "  stress     - 100 users, 20 requests each (2000 total requests)"
    echo "  custom     - Prompt for custom parameters"
    echo ""
    echo "Examples:"
    echo "  $0 --token abc123 --scenario light"
    echo "  $0 --token abc123 --auth-type offline-token --scenario heavy"
    echo "  $0 --token abc123 --url http://remote:8000/mcp --scenario stress"
}

run_test() {
    local users=$1
    local requests=$2
    local delay=$3
    local description=$4
    
    echo -e "${GREEN}Running $description...${NC}"
    echo "Configuration: $users users, $requests requests per user, ${delay}s delay"
    echo ""
    
    uv run --group performance integration_test/performance/performance_test.py \
        --url "$URL" \
        --token "$TOKEN" \
        --auth-type "$AUTH_TYPE" \
        --users "$users" \
        --requests "$requests" \
        --delay "$delay" \
        --save-results
    
    echo ""
    echo -e "${GREEN}$description completed.${NC}"
    echo "----------------------------------------"
}

run_custom_test() {
    echo -e "${YELLOW}Custom Performance Test Configuration${NC}"
    echo ""
    
    read -p "Number of concurrent users [10]: " users
    users=${users:-10}
    
    read -p "Number of requests per user [5]: " requests
    requests=${requests:-5}
    
    read -p "Delay between requests in seconds [0.1]: " delay
    delay=${delay:-0.1}
    
    run_test "$users" "$requests" "$delay" "Custom Test"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --auth-type)
            AUTH_TYPE="$2"
            shift 2
            ;;
        --scenario)
            SCENARIO="$2"
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Check if token is provided
if [[ -z "$TOKEN" ]]; then
    echo -e "${RED}Error: --token is required${NC}"
    print_usage
    exit 1
fi

# Check if Python dependencies are available
if ! python3 -c "import aiohttp" 2>/dev/null; then
    echo -e "${YELLOW}Warning: aiohttp not found. Installing performance dependencies...${NC}"
    uv sync --group performance
fi

echo -e "${GREEN}MCP Server Performance Test Suite${NC}"
echo "=================================="
echo "Server URL: $URL"
echo "Auth Type: $AUTH_TYPE"
echo ""

if [[ -z "$SCENARIO" ]]; then
    echo "Select a test scenario:"
    echo "1) Light (5 users, 3 requests each)"
    echo "2) Moderate (20 users, 5 requests each)"
    echo "3) Heavy (50 users, 10 requests each)"
    echo "4) Stress (100 users, 20 requests each)"
    echo "5) Custom (specify your own parameters)"
    echo ""
    read -p "Enter choice [1-5]: " choice
    
    case $choice in
        1) SCENARIO="light" ;;
        2) SCENARIO="moderate" ;;
        3) SCENARIO="heavy" ;;
        4) SCENARIO="stress" ;;
        5) SCENARIO="custom" ;;
        *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
    esac
fi

case $SCENARIO in
    light)
        run_test 5 3 0.1 "Light Load Test"
        ;;
    moderate)
        run_test 20 5 0.1 "Moderate Load Test"
        ;;
    heavy)
        run_test 50 10 0.05 "Heavy Load Test"
        ;;
    stress)
        run_test 100 20 0.02 "Stress Test"
        ;;
    custom)
        run_custom_test
        ;;
    *)
        echo -e "${RED}Unknown scenario: $SCENARIO${NC}"
        echo "Valid scenarios: light, moderate, heavy, stress, custom"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Performance test suite completed!${NC}"
echo "Check the generated JSON files for detailed results." 
