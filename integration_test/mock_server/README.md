# Mock Assisted Service API Server

This directory contains a Go-based mock HTTP server that simulates the Red Hat Assisted Service API endpoints. It's designed for testing and development purposes when you need to test the `assisted-service-mcp` without connecting to the actual Red Hat Assisted Service API.

## Location

The mock server is located at `integration_test/mock_server/` within the `assisted-service-mcp` repository.

## Features

The mock server provides realistic responses for the API endpoints used by the `InventoryClient` class in `service_client/assisted_service_api.py`:

### Supported Endpoints

#### Cluster Management
- `GET /api/assisted-install/v2/clusters` - List all clusters

#### Versions & Operators
- `GET /api/assisted-install/v2/openshift-versions` - List supported OpenShift versions (supports `?only_latest=true`)
- `GET /api/assisted-install/v2/operators/bundles` - List operator bundles

#### Health Check
- `GET /health` - Server health check

### Middleware Features

The mock server includes several middleware components for realistic testing:
- **Authentication**: Requires Bearer token authorization
- **Logging**: Request/response logging with timing information
- **Latency**: Simulates network delay (100ms per request)

## Building and Running

### Prerequisites

- Go 1.23.4 or later (as specified in go.mod)

### Build

```bash
cd integration_test/mock_server
go mod tidy
go build -o mock_server_go mock_server.go
```

### Run

```bash
./mock_server_go
```

The server will start on `http://0.0.0.0:8080`

### Using with Make

From the repo root:
```bash
# Run the Go mock server
make run-mock-assisted
```

This command will automatically change to the correct directory and run the server using `go run mock_server.go`.

## Sample Data

The mock server initializes with sample data including:
- One sample cluster with ID generated using UUID v4
- Two OpenShift versions (4.14.10 and 4.15.2)
- Two operator bundles (ODF and Logging)
