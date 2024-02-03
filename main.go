package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/go-kit/log"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	io_prometheus_client "github.com/prometheus/client_model/go"
	promConfig "github.com/prometheus/common/config"
	"gopkg.in/yaml.v2"
)

// version
// use go build -ldflags="-X main.version=$(git describe --tags)" main.go
var version string = "dev"

// Structs
type JSONICMPProbe struct {
	PreferredIPProtocol string `json:"preferred_ip_protocol,omitempty" yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback  bool   `json:"ip_protocol_fallback,omitempty" yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress     string `json:"source_ip_address,omitempty" yaml:"source_ip_address,omitempty"`
	PayloadSize         int    `json:"payload_size,omitempty" yaml:"payload_size,omitempty"`
	DontFragment        bool   `json:"dont_fragment,omitempty" yaml:"dont_fragment,omitempty"`
	TTL                 int    `json:"ttl,omitempty" yaml:"ttl,omitempty"`
}

type JSONDNSRRValidator struct {
	FailIfMatchesRegexp     []string `json:"fail_if_matches_regexp,omitempty" yaml:"fail_if_matches_regexp,omitempty"`
	FailIfAllMatchRegexp    []string `json:"fail_if_all_match_regexp,omitempty" yaml:"fail_if_all_match_regexp,omitempty"`
	FailIfNotMatchesRegexp  []string `json:"fail_if_not_matches_regexp,omitempty" yaml:"fail_if_not_matches_regexp,omitempty"`
	FailIfNoneMatchesRegexp []string `json:"fail_if_none_matches_regexp,omitempty" yaml:"fail_if_none_matches_regexp,omitempty"`
}

type JSONDNSProbe struct {
	IPProtocol         string               `json:"preferred_ip_protocol,omitempty" yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool                 `json:"ip_protocol_fallback,omitempty" yaml:"ip_protocol_fallback,omitempty"`
	DNSOverTLS         bool                 `json:"dns_over_tls,omitempty" yaml:"dns_over_tls,omitempty"`
	TLSConfig          promConfig.TLSConfig `json:"tls_config,omitempty" yaml:"tls_config,omitempty"`
	SourceIPAddress    string               `json:"source_ip_address,omitempty" yaml:"source_ip_address,omitempty"`
	TransportProtocol  string               `json:"transport_protocol,omitempty" yaml:"transport_protocol,omitempty"`
	QueryClass         string               `json:"query_class,omitempty" yaml:"query_class,omitempty"` // Defaults to IN.
	QueryName          string               `json:"query_name,omitempty" yaml:"query_name,omitempty"`
	QueryType          string               `json:"query_type,omitempty" yaml:"query_type,omitempty"`               // Defaults to ANY.
	Recursion          bool                 `json:"recursion_desired,omitempty" yaml:"recursion_desired,omitempty"` // Defaults to true.
	ValidRcodes        []string             `json:"valid_rcodes,omitempty" yaml:"valid_rcodes,omitempty"`           // Defaults to NOERROR.
	ValidateAnswer     JSONDNSRRValidator   `json:"validate_answer_rrs,omitempty" yaml:"validate_answer_rrs,omitempty"`
	ValidateAuthority  JSONDNSRRValidator   `json:"validate_authority_rrs,omitempty" yaml:"validate_authority_rrs,omitempty"`
	ValidateAdditional JSONDNSRRValidator   `json:"validate_additional_rrs,omitempty" yaml:"validate_additional_rrs,omitempty"`
}

// ProbeRequest represents the JSON structure for incoming probe requests.
type ProbeRequest struct {
	Target  string         `json:"target"`
	Timeout time.Duration  `json:"timeout"`
	ICMP    *JSONICMPProbe `json:"icmp,omitempty"`
	DNS     *JSONDNSProbe  `json:"dns,omitempty"`
	Debug   bool           `json:"debug"`
}

// ProbeResults represents the outcome of a probe.
type ProbeResults struct {
	Success bool                     `json:"success"`
	Metrics []map[string]interface{} `json:"metrics,omitempty"`
	Logs    []string                 `json:"logs"`
}

type bufferLogger struct {
	logs   []string
	logger log.Logger
}

type StatusReturn struct {
	Version string `json:"version"`
	Ready   bool   `json:"ready"`
}

// Custom logger to return logs as JSON  array
func newBufferLogger() *bufferLogger {
	var buf bytes.Buffer
	logger := log.NewLogfmtLogger(&buf)
	return &bufferLogger{
		logs:   []string{},
		logger: logger,
	}
}

func (l *bufferLogger) Log(keyvals ...interface{}) error {
	var logEntry string
	for i, keyval := range keyvals {
		if i%2 == 0 {
			logEntry += fmt.Sprintf("%v=", keyval)
		} else {
			logEntry += fmt.Sprintf("%v ", keyval)
		}
	}
	l.logs = append(l.logs, strings.TrimSpace(logEntry))
	return l.logger.Log(keyvals...)
}

func (l *bufferLogger) Output() []string {
	return l.logs
}

// prometheus metrics to JSON converter
func convertMetricsToJSON(metricFamilies []*io_prometheus_client.MetricFamily) ([]map[string]interface{}, error) {
	var metrics []map[string]interface{}

	for _, mf := range metricFamilies {
		metric := map[string]interface{}{
			"name":   mf.GetName(),
			"help":   mf.GetHelp(),
			"type":   mf.GetType().String(),
			"values": []map[string]interface{}{},
		}

		for _, m := range mf.GetMetric() {
			value := map[string]interface{}{
				"labels":    convertLabelsToMap(m.GetLabel()),
				"timestamp": m.GetTimestampMs(),

				// TODO: adjust other metric types then GAUGE
				"value": m.GetGauge().GetValue(), // Simplified; adjust for different metric types
			}
			metric["values"] = append(metric["values"].([]map[string]interface{}), value)
		}

		metrics = append(metrics, metric)
	}

	return metrics, nil
}

func convertLabelsToMap(labels []*io_prometheus_client.LabelPair) map[string]string {
	labelMap := make(map[string]string)
	for _, label := range labels {
		labelMap[label.GetName()] = label.GetValue()
	}
	return labelMap
}

// get Module
func getModuleType(module ProbeRequest) string {
	if module.ICMP != nil {
		return "ICMP"
	} else if module.DNS != nil {
		return "DNS"
	}
	return "Unknown"
}

// handleProbe preparse the config.Module configuration fot the probe that gets executed
func handleProbe(w http.ResponseWriter, r *http.Request) {
	var req ProbeRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Error decoding request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Convert JSON Module to YAML
	yamlData, err := yaml.Marshal(req)
	if err != nil {
		http.Error(w, "Error converting JSON to YAML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Unmarshal YAML into config.Module
	var module config.Module
	err = yaml.Unmarshal(yamlData, &module)
	if err != nil {
		http.Error(w, "Error parsing YAML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// // Marshal the module back into YAML for printing
	// moduleYAML, err := yaml.Marshal(module)
	// if err != nil {
	// 	fmt.Println("Error marshaling module back to YAML:", err)
	// 	return
	// }

	// // Print the module in YAML format
	// fmt.Printf("YAML Data:\n%s\n", string(yamlData))
	// fmt.Printf("Module in YAML format:\n%s\n", string(moduleYAML))

	// Set timeout
	module.Timeout = time.Second * req.Timeout

	probeType := getModuleType(req)
	results, err := executeProbe(req.Target, module, probeType, req.Debug)
	if err != nil {
		http.Error(w, "Error executing probe: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(results)
}

// executeProbe executes the actuall probe
func executeProbe(target string, module config.Module, probeType string, debug bool) (ProbeResults, error) {
	registry := prometheus.NewRegistry()

	// Use the custom buffer logger
	bufLogger := newBufferLogger()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), module.Timeout)
	defer cancel()

	// set probe_duration_seconds
	probeDurationGauge := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
	startTime := time.Now()

	// Execute probe
	var success bool
	switch probeType {
	case "ICMP":
		success = prober.ProbeICMP(ctx, target, module, registry, bufLogger)
	case "DNS":
		success = prober.ProbeDNS(ctx, target, module, registry, bufLogger)
	}

	duration := time.Since(startTime).Seconds()
	probeDurationGauge.Set(duration)

	// set probe_success
	probeSuccessGauge := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})

	if success {
		probeSuccessGauge.Set(1)
	} else {
		probeSuccessGauge.Set(0)
	}

	// Gather the metrics from the registry
	metricFamilies, err := registry.Gather()
	if err != nil {
		return ProbeResults{}, fmt.Errorf("error gathering metrics: %v", err)
	}

	// Convert metrics to JSON-friendly format
	jsonMetrics, err := convertMetricsToJSON(metricFamilies)
	if err != nil {
		return ProbeResults{}, fmt.Errorf("error converting metrics to JSON: %v", err)
	}

	var loggerOutput []string
	if debug {
		loggerOutput = bufLogger.Output()
	}

	return ProbeResults{
		Success: success,
		Metrics: jsonMetrics,
		Logs:    loggerOutput,
	}, nil
}

// Auth
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header from the request
		authHeader := r.Header.Get("Authorization")
		expectedString := os.Getenv("BLACKBOX_EXPORTER_AUTH")

		if expectedString != "disabled" && expectedString != authHeader {
			http.Error(w, "{\"msg\": \"Unauthorized\"}", http.StatusUnauthorized)
			return
		}

		// If authorized, call the next handler
		next(w, r)
	}
}

// handleStatus gives back the probe status and version
func handleStatus(w http.ResponseWriter, r *http.Request) {
	result := StatusReturn{
		Version: version,
		Ready:   true,
	}
	json.NewEncoder(w).Encode(result)
}

// Handle http requests
func webserver(stdLogger log.Logger) {
	stdLogger.Log("message", "Running webserver")
	httpPort := os.Getenv("BLACKBOX_EXPORTER_HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}
	stdLogger.Log("message", "Server started", "port", httpPort)

	http.HandleFunc("/status", authMiddleware(handleStatus))
	http.HandleFunc("/probe", authMiddleware(handleProbe))

	// Catch-all route for logging and returning a 404
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stdLogger.Log("error", "Page not found", "path", r.URL.Path)
		http.NotFound(w, r)
		return
	})

	http.ListenAndServe(":"+httpPort, nil)
}

func awslambda(stdLogger log.Logger) {
	stdLogger.Log("message", "Running in Lambda")
	http.HandleFunc("/status", authMiddleware(handleStatus))
	http.HandleFunc("/probe", authMiddleware(handleProbe))

	http.HandleFunc("/default/status", handleStatus)
	http.HandleFunc("/", handleStatus)

	// Catch-all route for logging and returning a 404
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stdLogger.Log("error", "Page not found", "path", r.URL.Path)
		http.NotFound(w, r)
		return
	})

	adapter := httpadapter.New(http.DefaultServeMux)
	lambda.Start(adapter.ProxyWithContext)
}

func isRunningInLambda() bool {
	functionName := os.Getenv("AWS_LAMBDA_FUNCTION_NAME")
	return functionName != ""
}

func main() {
	stdLogger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	stdLogger = log.With(stdLogger, "ts", log.TimestampFormat(time.Now, time.RFC3339))
	stdLogger = log.With(stdLogger, "caller", log.DefaultCaller)

	if os.Getenv("BLACKBOX_EXPORTER_AUTH") == "disabled" {
		stdLogger.Log("message", "Authentication is disabled")
	}

	if isRunningInLambda() {
		awslambda(stdLogger)
	} else {
		webserver(stdLogger)
	}
}
