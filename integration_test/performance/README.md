# MCP Server Performance Testing

This directory contains performance testing tools for the Assisted Service MCP Server. These tools help evaluate the server's behavior under concurrent load from multiple users.

## Quick Start

### Prerequisites

1. **Python dependencies**: Install performance testing dependencies using uv:
   ```bash
   uv sync --group performance
   ```

2. **Running Mock Server**:
   ```bash
   # In one terminal, start the mock assisted service API
   make run-mock-assisted
   ```

3. **Running MCP Server**:
   ```bash
   TRANSPORT=streamable-http INVENTORY_URL="http://localhost:8080/api/assisted-install/v2" uv run server.py
   ```

### Running Tests

#### Option 1: Simple Shell Script (Recommended)

```bash
# Light load test (15 requests)
./run_performance_test.sh --token mocktoken --scenario light

# Heavy load test (500 requests)
./run_performance_test.sh --token mocktoken --scenario heavy

# Interactive mode (prompts for parameters)
./run_performance_test.sh --token mocktoken
```

#### Option 2: Direct Python Script

```bash
# Basic test with 10 users making 5 requests each
uv run --group performance python3 performance_test.py --token mocktoken --users 10 --requests 5

# Stress test with 100 users
uv run --group performance python3 performance_test.py --token mocktoken --users 100 --requests 20 --delay 0.02
```

## Test Scenarios

| Scenario | Users | Requests per User | Total Requests | Use Case |
|----------|-------|-------------------|----------------|----------|
| Light    | 5     | 3                 | 15             | Basic functionality test |
| Moderate | 20    | 5                 | 100            | Normal load simulation |
| Heavy    | 50    | 10                | 500            | High load testing |
| Stress   | 100   | 20                | 2000           | Maximum capacity testing |
| Custom   | -     | -                 | -              | User-defined parameters |

## Command Line Options

### performance_test.py

```bash
uv run --group performance python3 performance_test.py [OPTIONS]

Options:
  --url URL              MCP server URL (default: http://localhost:8000/mcp)
  --token TOKEN          Authentication token (required)
  --auth-type TYPE       Auth type: bearer or offline-token (default: bearer)
  --users NUM            Number of concurrent users (default: 10)
  --requests NUM         Number of requests per user (default: 5)
  --delay SECONDS        Delay between requests from same user (default: 0.1)
```

### run_performance_test.sh

```bash
./run_performance_test.sh [OPTIONS] --token TOKEN

Options:
  --token TOKEN          Authentication token (required)
  --url URL             MCP server URL (default: http://localhost:8000/mcp)
  --auth-type TYPE      Auth type: bearer or offline-token (default: bearer)
  --scenario SCENARIO   Test scenario: light, moderate, heavy, stress, custom
  --help                Show help message
```

## What Gets Tested

The performance tests simulate realistic usage by calling different MCP tools with weighted distribution:

- **list_clusters** (40% of requests) - Most common operation
- **list_versions** (30% of requests) - Version lookup
- **list_operator_bundles** (20% of requests) - Operator information
- **tools/list** (10% of requests) - Tool discovery

## Output and Results

### Console Output

The script provides real-time progress and detailed results including:

- **Summary Statistics**: Total requests, success rate, requests/second
- **Response Time Statistics**: Average, min, max, 95th/99th percentiles
- **Tool Performance Breakdown**: Per-tool success rates and response times
- **Error Analysis**: Detailed breakdown of any failures

### Example Output

```
============================================================
PERFORMANCE TEST RESULTS
============================================================
Test completed at: 2024-01-15 14:30:45

SUMMARY STATISTICS:
  Total Duration:        12.34 seconds
  Total Requests:        100
  Successful Requests:   98
  Failed Requests:       2
  Success Rate:          98.00%
  Error Rate:            2.00%
  Requests/Second:       8.10

RESPONSE TIME STATISTICS:
  Average:               0.245s
  Minimum:               0.120s
  Maximum:               1.200s
  95th Percentile:       0.450s
  99th Percentile:       0.890s

TOOL PERFORMANCE BREAKDOWN:
  list_clusters              40 requests,  100.0% success,    0.230s avg
  list_versions              30 requests,   96.7% success,    0.280s avg
  list_operator_bundles      20 requests,  100.0% success,    0.210s avg
  tools_list                 10 requests,  100.0% success,    0.150s avg
```

### JSON Results File

Each test run generates a timestamped JSON file (e.g., `performance_test_results_20240115_143045.json`) containing:

- **Summary Statistics**: All metrics from console output
- **Raw Results**: Individual request details for analysis
  - Response times, status codes, errors
  - User ID and tool name for each request
  - Success/failure status
