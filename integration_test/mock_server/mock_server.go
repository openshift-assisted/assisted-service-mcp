package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Data structures matching the Python server

type Cluster struct {
	ID                       string   `json:"id"`
	Href                     string   `json:"href"`
	Kind                     string   `json:"kind"`
	Name                     string   `json:"name"`
	OpenShiftVersion         string   `json:"openshift_version"`
	Status                   string   `json:"status"`
	StatusInfo               string   `json:"status_info"`
	BaseDNSDomain            string   `json:"base_dns_domain"`
	ClusterNetworkCIDR       string   `json:"cluster_network_cidr"`
	ClusterNetworkHostPrefix int      `json:"cluster_network_host_prefix"`
	ServiceNetworkCIDR       string   `json:"service_network_cidr"`
	HighAvailabilityMode     string   `json:"high_availability_mode"`
	UserManagedNetworking    bool     `json:"user_managed_networking"`
	CreatedAt                string   `json:"created_at"`
	UpdatedAt                string   `json:"updated_at"`
	APIVips                  []string `json:"api_vips"`
	IngressVips              []string `json:"ingress_vips"`
	Hosts                    []string `json:"hosts"`
	TotalHostCount           int      `json:"total_host_count"`
	EnabledHostCount         int      `json:"enabled_host_count"`
	ReadyHostCount           int      `json:"ready_host_count"`
}

type OpenShiftVersion struct {
	DisplayName     string `json:"display_name"`
	ReleaseVersion  string `json:"release_version"`
	SupportLevel    string `json:"support_level"`
	CPUArchitecture string `json:"cpu_architecture"`
}

type OperatorBundle struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	Operators   []string `json:"operators"`
}

// In-memory storage
var clusters = make(map[string]Cluster)

// Sample data
var sampleOpenShiftVersions = map[string]OpenShiftVersion{
	"4.14.10": {
		DisplayName:     "4.14.10",
		ReleaseVersion:  "4.14.10",
		SupportLevel:    "production",
		CPUArchitecture: "x86_64",
	},
	"4.15.2": {
		DisplayName:     "4.15.2",
		ReleaseVersion:  "4.15.2",
		SupportLevel:    "production",
		CPUArchitecture: "x86_64",
	},
}

var sampleOperatorBundles = []OperatorBundle{
	{
		Name:        "odf-operator",
		DisplayName: "OpenShift Data Foundation",
		Description: "Provides persistent storage and data services",
		Operators:   []string{"odf-operator", "ocs-operator"},
	},
	{
		Name:        "logging",
		DisplayName: "OpenShift Logging",
		Description: "Centralized logging for OpenShift",
		Operators:   []string{"cluster-logging", "elasticsearch-operator"},
	},
}

// Middleware for adding latency (simulating network delay)
func latencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add 0.5 second latency to all requests
		time.Sleep(100 * time.Millisecond)
		next.ServeHTTP(w, r)
	})
}

// Middleware for authentication
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid authorization"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware for logging requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)
		log.Printf("%s %s - %d - %.2fms - %s",
			r.Method, r.URL.Path, wrapper.statusCode,
			float64(duration.Nanoseconds())/1e6, r.RemoteAddr)
	})
}

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Helper function to create a sample cluster
func createSampleCluster(clusterID, name, version string) Cluster {
	now := time.Now().UTC().Format(time.RFC3339) + "Z"
	return Cluster{
		ID:                       clusterID,
		Href:                     fmt.Sprintf("/api/assisted-install/v2/clusters/%s", clusterID),
		Kind:                     "Cluster",
		Name:                     name,
		OpenShiftVersion:         version,
		Status:                   "insufficient",
		StatusInfo:               "Cluster is not ready for installation",
		BaseDNSDomain:            "example.com",
		ClusterNetworkCIDR:       "10.128.0.0/14",
		ClusterNetworkHostPrefix: 23,
		ServiceNetworkCIDR:       "172.30.0.0/16",
		HighAvailabilityMode:     "Full",
		UserManagedNetworking:    false,
		CreatedAt:                now,
		UpdatedAt:                now,
		APIVips:                  []string{},
		IngressVips:              []string{},
		Hosts:                    []string{},
		TotalHostCount:           0,
		EnabledHostCount:         0,
		ReadyHostCount:           0,
	}
}

// Endpoint handlers

func listClusters(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterList := make([]Cluster, 0, len(clusters))
	for _, cluster := range clusters {
		clusterList = append(clusterList, cluster)
	}

	json.NewEncoder(w).Encode(clusterList)
}

func listOpenShiftVersions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	onlyLatest := r.URL.Query().Get("only_latest")
	if onlyLatest == "true" {
		// Return only the latest version (4.15.2)
		latestVersions := map[string]OpenShiftVersion{
			"4.15.2": sampleOpenShiftVersions["4.15.2"],
		}
		json.NewEncoder(w).Encode(latestVersions)
	} else {
		json.NewEncoder(w).Encode(sampleOpenShiftVersions)
	}
}

func listOperatorBundles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sampleOperatorBundles)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339) + "Z",
	}
	json.NewEncoder(w).Encode(response)
}

// newUUID generates a random UUID according to RFC 4122
// and returns it as a formatted string.
func newUUID() string {
	uuid := make([]byte, 16)
	n, err := rand.Read(uuid)
	if n != 16 || err != nil {
		panic(fmt.Sprintf("failed to generate uuid: %w", err))
	}
	// Set the version to 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set the variant to RFC 4122
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	// Format the UUID into the standard string representation
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

// Initialize sample data
func initializeSampleData() {
	clusterID := newUUID()
	cluster := createSampleCluster(clusterID, "sample-cluster", "4.14.10")
	clusters[clusterID] = cluster
	log.Printf("Initialized sample cluster: %s", clusterID)
}

func main() {
	// Initialize sample data
	initializeSampleData()

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Register endpoint handlers
	mux.HandleFunc("/api/assisted-install/v2/clusters", listClusters)
	mux.HandleFunc("/api/assisted-install/v2/openshift-versions", listOpenShiftVersions)
	mux.HandleFunc("/api/assisted-install/v2/operators/bundles", listOperatorBundles)
	mux.HandleFunc("/health", healthCheck)

	// Apply middleware chain
	handler := loggingMiddleware(latencyMiddleware(authMiddleware(mux)))

	// Configure server
	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	log.Printf("Starting mock server on http://0.0.0.0:8080")
	log.Fatal(server.ListenAndServe())
}
