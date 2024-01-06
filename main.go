package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v2"
)

// Structs
type JSONICMPProbe struct {
	PreferredIPProtocol string `json:"preferred_ip_protocol,omitempty" yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback  bool   `json:"ip_protocol_fallback,omitempty" yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress     string `json:"source_ip_address,omitempty" yaml:"source_ip_address,omitempty"`
	PayloadSize         int    `json:"payload_size,omitempty" yaml:"payload_size,omitempty"`
	DontFragment        bool   `json:"dont_fragment,omitempty" yaml:"dont_fragment,omitempty"`
	TTL                 int    `json:"ttl,omitempty" yaml:"ttl,omitempty"`
}

type JSONProbeModule struct {
	ICMP *JSONICMPProbe `json:"icmp,omitempty"`
}

// ProbeRequest represents the JSON structure for incoming probe requests.
type ProbeRequest struct {
	Target  string         `json:"target"`
	Timeout time.Duration  `json:"timeout"`
	ICMP    *JSONICMPProbe `json:"icmp,omitempty"`
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

	results, err := executeProbe(req.Target, module, req.Debug)
	if err != nil {
		http.Error(w, "Error executing probe: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(results)
}

// executeProbe executes the actuall probe
func executeProbe(target string, module config.Module, debug bool) (ProbeResults, error) {
	registry := prometheus.NewRegistry()

	// Use the custom buffer logger
	bufLogger := newBufferLogger()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), module.Timeout)
	defer cancel()

	// Execute the ICMP probe
	startTime := time.Now()
	success := prober.ProbeICMP(ctx, target, module, registry, bufLogger)

	// set probe_duration_seconds
	probeDurationGauge := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
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

// Handle http requests
func main() {
	http.HandleFunc("/probe", handleProbe)
	http.ListenAndServe(":8080", nil)
}
