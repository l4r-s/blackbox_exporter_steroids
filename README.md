# Blackbox exporter HTTP JSON wrapper

This project wrapps the awesome [Prometheus Blackbox Exporter](https://github.com/prometheus/blackbox_exporter) as a http json websever.

## Start

Start the server with:

```
go run main.go
```

## Authentication

Authentication is handled with a bcrypted hash. Specify it as Environment variable:

```
export BLACKBOX_EXPORTER_AUTH='$2a$10$W87Ftk.jaLEVbuWsMWz9Q.dSejNlqatKyUKQu5ZLNB8Ny3ZmHfDiW'
```

Authentication can be disabled with:
```
export BLACKBOX_EXPORTER_AUTH='disabled'
```


## Examples

### ICMP

```
curl -s -X POST http://localhost:8080/probe -d '{"target": "1.1.1.1", "icmp": { "preferred_ip_protocol": "ip4" }, "timeout": 2 , "debug": true}'| jq
{
  "success": true,
  "metrics": [
    {
      "help": "Returns the time taken for probe dns lookup in seconds",
      "name": "probe_dns_lookup_time_seconds",
      "type": "GAUGE",
      "values": [
        {
          "labels": {},
          "timestamp": 0,
          "value": 0.00000775
        }
      ]
    },
    {
      "help": "Returns how long the probe took to complete in seconds",
      "name": "probe_duration_seconds",
      "type": "GAUGE",
      "values": [
        {
          "labels": {},
          "timestamp": 0,
          "value": 0.009431791
        }
      ]
    },
    {
      "help": "Duration of icmp request by phase",
      "name": "probe_icmp_duration_seconds",
      "type": "GAUGE",
      "values": [
        {
          "labels": {
            "phase": "resolve"
          },
          "timestamp": 0,
          "value": 0.00000775
        },
        {
          "labels": {
            "phase": "rtt"
          },
          "timestamp": 0,
          "value": 0.009275083
        },
        {
          "labels": {
            "phase": "setup"
          },
          "timestamp": 0,
          "value": 0.000061458
        }
      ]
    },
    {
      "help": "Replied packet hop limit (TTL for ipv4)",
      "name": "probe_icmp_reply_hop_limit",
      "type": "GAUGE",
      "values": [
        {
          "labels": {},
          "timestamp": 0,
          "value": 52
        }
      ]
    },
    {
      "help": "Specifies the hash of IP address. It's useful to detect if the IP address changes.",
      "name": "probe_ip_addr_hash",
      "type": "GAUGE",
      "values": [
        {
          "labels": {},
          "timestamp": 0,
          "value": 357429369
        }
      ]
    },
    {
      "help": "Specifies whether probe ip protocol is IP4 or IP6",
      "name": "probe_ip_protocol",
      "type": "GAUGE",
      "values": [
        {
          "labels": {},
          "timestamp": 0,
          "value": 4
        }
      ]
    },
    {
      "help": "Displays whether or not the probe was a success",
      "name": "probe_success",
      "type": "GAUGE",
      "values": [
        {
          "labels": {},
          "timestamp": 0,
          "value": 1
        }
      ]
    }
  ],
  "logs": [
    "level=info msg=Resolving target address target=1.1.1.1 ip_protocol=ip4",
    "level=info msg=Resolved target address target=1.1.1.1 ip=1.1.1.1",
    "level=info msg=Creating socket",
    "level=info msg=Creating ICMP packet seq=22278 id=11830",
    "level=info msg=Writing out packet",
    "level=debug msg=Setting TTL (IPv4 unprivileged) ttl=64",
    "level=info msg=Waiting for reply packets",
    "level=info msg=Found matching reply packet"
  ]
}
```


