package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testCaseLabel struct {
	Key   string
	Value string
}

type testCaseValue struct {
	Value  float64
	Labels []testCaseLabel
}

type testCaseMetric struct {
	Name   string
	Type   string
	Values []testCaseValue
}

type testCaseExpected struct {
	StatusCode int
	Success    bool
	LogsNil    bool
	Metrics    []testCaseMetric
}

type testCase struct {
	Name        string
	JsonPayload string
	Expected    testCaseExpected
}

// intPtr helps create an *int from an int.
func floatPtr(i float64) *float64 {
	return &i
}

// TODO: implement labels check
var ICMPMetrics = []testCaseMetric{
	{
		Name: "probe_dns_lookup_time_seconds",
		Type: "GAUGE",
	},

	{
		Name: "probe_duration_seconds",
		Type: "GAUGE",
	},

	{
		Name: "probe_icmp_duration_seconds",
		Type: "GAUGE",
		Values: []testCaseValue{
			{
				// Any value is ok
				Value: 99999,
				Labels: []testCaseLabel{
					{Key: "phase", Value: "resolve"},
				},
			},

			{
				Value: 99999,
				Labels: []testCaseLabel{
					{Key: "phase", Value: "rtt"},
				},
			},

			{
				Value: 99999,
				Labels: []testCaseLabel{
					{Key: "phase", Value: "setup"},
				},
			},
		},
	},

	{
		Name: "probe_icmp_reply_hop_limit",
		Type: "GAUGE",
	},

	{
		Name: "probe_ip_addr_hash",
		Type: "GAUGE",
	},

	{
		Name: "probe_ip_protocol",
		Type: "GAUGE",
	},

	{
		Name: "probe_success",
		Type: "GAUGE",
		Values: []testCaseValue{
			{
				Value: 1,
			},
		},
	},
}

var ICMPMetricsUnavailable = []testCaseMetric{
	{
		Name: "probe_success",
		Type: "GAUGE",
		Values: []testCaseValue{
			{Value: 0},
		},
	},
}

var DNSMetrics = []testCaseMetric{
	{
		Name: "probe_dns_additional_rrs",
		Type: "GAUGE",
	},

	{
		Name: "probe_dns_answer_rrs",
		Type: "GAUGE",
	},

	{
		Name: "probe_dns_authority_rrs",
		Type: "GAUGE",
	},

	{
		Name: "probe_dns_duration_seconds",
		Type: "GAUGE",
		Values: []testCaseValue{
			{
				// Any value is ok
				Value: 99999,
				Labels: []testCaseLabel{
					{Key: "phase", Value: "connect"},
				},
			},

			{
				Value: 99999,
				Labels: []testCaseLabel{
					{Key: "phase", Value: "request"},
				},
			},

			{
				Value: 99999,
				Labels: []testCaseLabel{
					{Key: "phase", Value: "resolve"},
				},
			},
		},
	},

	{
		Name: "probe_dns_lookup_time_seconds",
		Type: "GAUGE",
	},

	{
		Name: "probe_dns_query_succeeded",
		Type: "GAUGE",
	},

	{
		Name: "probe_duration_seconds",
		Type: "GAUGE",
	},

	{
		Name: "probe_ip_addr_hash",
		Type: "GAUGE",
	},

	{
		Name: "probe_ip_protocol",
		Type: "GAUGE",
	},

	{
		Name: "probe_success",
		Type: "GAUGE",
		Values: []testCaseValue{
			{
				Value: 1,
			},
		},
	},
}

func TestHandleProbes(t *testing.T) {
	testCases := []testCase{
		// ICMPv4
		{
			Name: "IPv4 ICMP available",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    true,
				LogsNil:    false,
				Metrics:    ICMPMetrics,
			},
			JsonPayload: `{
				"target": "8.8.8.8",
				"timeout": 5,
				"icmp": {
					"preferred_ip_protocol": "ip4",
					"ip_protocol_fallback": false
				},
				"debug": true
			}`,
		},
		{
			Name: "IPv4 ICMP available, no debug",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    true,
				LogsNil:    true,
				Metrics:    ICMPMetrics,
			},
			JsonPayload: `{
				"target": "1.1.1.1",
				"timeout": 5,
				"icmp": {
					"preferred_ip_protocol": "ip4",
					"ip_protocol_fallback": false
				},
				"debug": false
			}`,
		},
		{
			Name: "IPv4 ICMP not available",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    false,
				LogsNil:    false,
				Metrics:    ICMPMetricsUnavailable,
			},
			JsonPayload: `{
				"target": "192.168.233.199",
				"timeout": 2,
				"icmp": {
					"preferred_ip_protocol": "ip4",
					"ip_protocol_fallback": false
				},
				"debug": true
			}`,
		},

		// ICMPv6
		{
			Name: "IPv6 ICMP available",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    true,
				LogsNil:    false,
				Metrics:    ICMPMetrics,
			},
			JsonPayload: `{
				"target": "2606:4700:4700::64",
				"timeout": 5,
				"icmp": {
					"preferred_ip_protocol": "ip6",
					"ip_protocol_fallback": false
				},
				"debug": true
			}`,
		},
		{
			Name: "IPv6 ICMP not available",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    false,
				LogsNil:    false,
				Metrics:    ICMPMetricsUnavailable,
			},
			JsonPayload: `{
				"target": "fe80:22",
				"timeout": 2,
				"icmp": {
					"preferred_ip_protocol": "ip6",
					"ip_protocol_fallback": false
				},
				"debug": true
			}`,
		},

		// DNS
		{
			Name: "DNS A record",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    true,
				LogsNil:    false,
				Metrics:    DNSMetrics,
			},
			JsonPayload: `{
				"target": "1.1.1.1",
				"timeout": 2,
				"dns": {
					"preferred_ip_protocol": "ip4",
					"query_name": "google.com",
					"query_type": "A"
				},
				"debug": true
			}`,
		},

		{
			Name: "DNS AAAA record",
			Expected: testCaseExpected{
				StatusCode: http.StatusOK,
				Success:    true,
				LogsNil:    false,
				Metrics:    DNSMetrics,
			},
			JsonPayload: `{
				"target": "1.1.1.1",
				"timeout": 2,
				"dns": {
					"preferred_ip_protocol": "ip6",
					"query_name": "google.com",
					"query_type": "AAAA"
				},
				"debug": true
			}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Create a new HTTP request with the JSON string as the body
			req, err := http.NewRequest("POST", "/probe", strings.NewReader(tc.JsonPayload))
			if err != nil {
				t.Fatalf("Failed to create HTTP request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// Create a ResponseRecorder to record the response
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(handleProbe)

			// Perform the test
			handler.ServeHTTP(rr, req)

			// Check the status code
			if status := rr.Code; status != tc.Expected.StatusCode {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, tc.Expected.StatusCode)
			}

			// Read the response body and unmarshal the response body into the expected structure
			responseBody := rr.Body.Bytes()
			var result ProbeResults
			err = json.Unmarshal(responseBody, &result)
			if err != nil {
				t.Fatalf("Failed to unmarshal response body: %v", err)
			}

			// Format the response body for pretty printing
			var prettyJSON bytes.Buffer
			error := json.Indent(&prettyJSON, responseBody, "", "    ")
			if error != nil {
				t.Fatalf("Failed to format JSON: %v", err)
			}

			// Check if the success key is true
			if !result.Success == tc.Expected.Success {
				t.Errorf("Expected success to be %v, got false. Response body:\n%s", tc.Expected.Success, prettyJSON.String())
			}

			// Check if logs exist
			if tc.Expected.LogsNil {
				if len(result.Logs) != 0 {
					t.Errorf("Expected logs to be null, got %v Logs. Response body:\n%s", len(result.Logs), prettyJSON.String())
				}
			}

			if !tc.Expected.LogsNil {
				if len(result.Logs) == 0 {
					t.Errorf("Expected logs to not be null, got 0 Logs. Response body:\n%s", prettyJSON.String())
				}
			}

			// Check metrics
			for _, expected := range tc.Expected.Metrics {
				var foundName bool = false
				for _, metric := range result.Metrics {
					// Metric Name
					if metricName, ok := metric["name"]; ok && metricName == expected.Name {
						foundName = true

						// Metric Type
						if metric["type"] != expected.Type {
							t.Errorf("Expected type for metric %s should be %s but received %s.\n", expected.Name, expected.Type, metric["type"])
						}

						// Values
						if values, ok := metric["values"].([]interface{}); ok {
							for valueIndex, valueInterface := range values {
								if valueIndex <= len(expected.Values) && len(expected.Values) != 0 {
									valueMap, ok := valueInterface.(map[string]interface{})
									if !ok {
										t.Errorf("No values for metric %s\n", metricName)
										continue
									}

									// Check labels
									if labels, ok := valueMap["labels"].(map[string]interface{}); ok {
										for _, expectedLabel := range expected.Values[valueIndex].Labels {
											if labelValue, ok := labels[expectedLabel.Key]; ok {
												if labelValue != expectedLabel.Value {
													t.Errorf("Value for label %s is not %s. Received %v\n", expectedLabel.Key, expectedLabel.Value, labelValue)
												}
											} else {
												t.Errorf("Label %s not found for metric %s\n", expectedLabel.Key, metricName)
											}
										}
									}

									// if timestamp, ok := valueMap["timestamp"].(int64); ok {
									// 	// Access and process timestamp
									// }
									if value, ok := valueMap["value"].(float64); ok {
										// if Value == 99999 any Value is fine
										if value != expected.Values[valueIndex].Value && expected.Values[valueIndex].Value != 99999 {
											t.Errorf("Value for metric %s on index %v is wrong. Expected %v but received %v\n", metricName, valueIndex, expected.Values[valueIndex].Value, value)
										}
									}
								}

							}
						}

						break
					}
				}
				if !foundName {
					t.Errorf("Expected metric %s not found in response. Response body:\n%s", expected.Name, prettyJSON.String())
				}
			}

		})
	}
}
