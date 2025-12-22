# shodan-sec-monitor

Shodan Security Monitor is a passive security monitoring tool that uses the Shodan API to track the external exposure of IP addresses you own or manage.

The project does **not perform active scanning**. It relies exclusively on Shodan’s indexed data to collect information about exposed services, software versions, and known vulnerabilities, storing everything in PostgreSQL for historical analysis and reporting.

The goal is to help security, SRE, and DevOps teams understand how their public attack surface evolves over time.

---

## features

- passive monitoring via Shodan API
- no active scanning or probing
- collection of services, banners, and vulnerabilities
- PostgreSQL storage for historical tracking
- simple service risk scoring
- supports one-shot runs or scheduled execution
- designed to run locally, in Docker, or Kubernetes

---

## Architecture overview

1. The collector reads a list of target IP addresses
2. For each IP, it queries the Shodan API
3. Results are normalized and stored in PostgreSQL
4. Each execution is tracked as a scan run
5. Services and vulnerabilities can be queried over time

This makes it easy to answer questions like:
- what new services appeared last week?
- which IPs expose high-risk software?
- how has the attack surface changed over time?

---

## Requirements

- Shodan API key
- PostgreSQL database
- Python 3.10+ (if running without Docker)

---

## Configuration

### Required environment variables

```
SHODAN_API_KEY=your_shodan_api_key
DB_HOST=postgres
DB_NAME=shodan
DB_USER=shodan
DB_PASS=shodan
TARGETS_WEB=1.2.3.4,5.6.7.8
```

```TARGETS_WEB``` must be a comma-separated list of IPv4 addresses you own or are authorised to monitor.

### Optional environment variables
```
INTERVAL_SECONDS=21600   # default: 6 hours
REQUEST_DELAY=1.0        # delay between Shodan API requests
LOG_LEVEL=INFO
```
### Running with docker

Example docker run command:

```
docker run -d \
  --name shodan-sec-monitor \
  -e SHODAN_API_KEY="your_key" \
  -e TARGETS_WEB="1.2.3.4,5.6.7.8" \
  -e DB_HOST="postgres" \
  -e DB_NAME="shodan" \
  -e DB_USER="shodan" \
  -e DB_PASS="shodan" \
  shodan-sec-monitor
```

Make sure PostgreSQL is reachable from the container.

### Running on kubernetes (k3s example)

Example configuration using ConfigMap and Secret:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: shodan-config
data:
  TARGETS_WEB: "1.2.3.4,5.6.7.8"
  INTERVAL_SECONDS: "21600"

apiVersion: v1
kind: Secret
metadata:
  name: shodan-secrets
type: Opaque
stringData:
  SHODAN_API_KEY: your_key
  DB_PASS: shodan
```

Mount these into the container as environment variables.

### Usage
validate configuration
```python scripts/run_collector.py --validate```


### Checks connectivity to Shodan and PostgreSQL without running a scan.

Run a single collection
```python scripts/run_collector.py --once```


### Executes one scan cycle and exits.

Run continuously

```python scripts/run_collector.py```


### Runs in a loop using INTERVAL_SECONDS.

Show statistics

```python scripts/run_collector.py --stats```


### Displays information about stored scans and targets.

Cleanup stuck scans

``` python scripts/clean_stuck_scans.py --cleanup-stuck```

Marks interrupted or unfinished scan runs as failed.

### Database schema overview

The PostgreSQL database stores:

```scan_runs```
Tracks each execution, start/end time, and status

```targets```
IP metadata such as ASN, country, and organisation

```services```
Open ports, detected software, versions, banners, and risk score

```vulns```
Known vulnerabilities (CVE-based) associated with services

### Example queries

High-risk services

```
SELECT
  t.ip,
  s.port,
  s.product,
  s.version,
  s.risk_score
FROM services s
JOIN targets t ON s.target_id = t.id
WHERE s.risk_score > 70
ORDER BY s.risk_score DESC;
```

Scan history

```
SELECT
  status,
  COUNT(*) AS runs,
  AVG(finished_at - started_at) AS avg_duration
FROM scan_runs
GROUP BY status;
```

Services with vulnerabilities

```
SELECT
  t.ip,
  s.port,
  s.product,
  s.vulns
FROM services s
JOIN targets t ON s.target_id = t.id
WHERE jsonb_array_length(s.vulns) > 0;
```

### Building the image

Multi-architecture build (amd64, arm64, arm/v7):

```./build.sh```

Manual build:

```
docker build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t your-registry/shodan-sec-monitor:latest \
  --push .
```
### Security considerations

This tool is passive only. It uses data already indexed by Shodan. It does not probe or scan hosts-
Only monitor IP addresses you own or are authorised to monitor.
Ensure your Shodan API plan supports the request volume.

### Licence

MIT License.
Use responsibly and only on authorised assets.
