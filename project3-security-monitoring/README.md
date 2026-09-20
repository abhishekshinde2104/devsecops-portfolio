# Security monitoring & detection stack

[![project3-security-monitoring](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project3-security-monitoring.yml/badge.svg)](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project3-security-monitoring.yml)

Prometheus, Alertmanager and Grafana (via the kube-prometheus-stack Helm
chart) monitoring the Project 1 API on the Project 2 hardened cluster —
framed around **attack detection, not uptime**. The API already exports
security counters (failed logins, rejected tokens, BOLA denials, SSRF blocks,
rate-limit rejections); this project turns them into detections, a dashboard,
routed alerts, and optional Falco runtime detection.

```
app /metrics ──▶ Prometheus ──▶ recording + alerting rules ──▶ Alertmanager ──▶ webhook sink
  (security         │                    │                        (route by        (SIEM stand-in)
   counters)        └──▶ Grafana dashboard│  team=security)
                                          └──▶ Falco (optional) ──▶ falcosidekick ─┘
```

## Detections

Ten+ rules in [`rules/security-alerts.rules.yaml`](rules/security-alerts.rules.yaml),
each mapped to a Project 1 control and an ATT&CK technique:

| Alert | Signal | Control | ATT&CK |
|---|---|---|---|
| BruteForceLogin | failed logins spike | SIA-06 | T1110 |
| CredentialStuffingThrottled | rate-limited logins spike | SIA-06 | T1110.004 |
| TokenTampering | rejected JWTs spike | SIA-02 | T1550.001 |
| BOLAProbing | cross-tenant invoice denials | SIA-01 | API1:2023 |
| PrivilegeEscalationAttempts | admin-endpoint denials | SIA-08 | T1068 |
| SSRFAttempts | outbound requests blocked | SIA-05 | A10:2021 |
| ReconScanning | 404 flood | – | T1595 |
| AbnormalRequestRate | req/s over baseline | – | T1498 |
| High5xxRate | 5xx ratio | – | – |
| ContainerRestarting | api restarts | – | T1499 |
| Down | target unscrapable | – | – |

Each alert has a [runbook entry](docs/runbook.md). Recording rules pre-compute
the shared expressions so the alerts and the Grafana dashboard use one
definition.

**Tested without a cluster:** the detection logic has a promtool unit-test
suite ([`rules/tests/`](rules/tests/security-alerts.test.yaml)) that drives
synthetic series through the real rules and asserts what fires — brute force,
BOLA, SSRF, privilege escalation, recon, 5xx, restarts, down, and a
healthy-traffic case that must stay silent.

## Dashboard

[`dashboards/invoice-api-security.json`](dashboards/invoice-api-security.json)
— "Invoice API – Security Overview": firing-alert count, failed/throttled
logins, cross-tenant lookups, rejected tokens by reason, authorization denials
by resource, SSRF blocks by reason, request status classes, rate-limiter
rejections, p95 latency, and the live alert list. Auto-provisioned into
Grafana via a labelled ConfigMap.

## Alert delivery

Alertmanager routes everything labelled `team: security` to a small **webhook
sink** ([`manifests/alert-sink.yaml`](manifests/alert-sink.yaml)) that stands
in for a SIEM/chat integration: it logs each alert as one JSON line and serves
the last 500 on `/alerts`, so the verification can prove **delivery**, not
just that a rule fired. A NetworkPolicy lets only Alertmanager (and
falcosidekick, with `--falco`) reach it.

## Runtime detection (optional)

`--falco` adds Falco (modern eBPF) with rules tuned to this workload — a shell
in the locked-down `invoice-api` container, or a write under its read-only
`/app`, is high-signal. falcosidekick forwards events to the same sink. Falco
runs in its own `falco` namespace, the one steady-state exemption from Pod
Security `restricted`.

## Run it

Prereqs: the Project 2 hardened cluster with the app deployed, plus `helm`.

```bash
# from repo root: hardened cluster + app (Project 2)
project2-k8s-hardening/scripts/cluster-up.sh hardened
project2-k8s-hardening/scripts/deploy.sh hardened

cd project3-security-monitoring
scripts/monitoring-up.sh              # Prometheus, Alertmanager, Grafana, rules, dashboard, sink
scripts/monitoring-up.sh --falco      # ...plus Falco

# prove the whole pipeline end to end (scrape -> rules -> dashboard -> alert -> sink)
scripts/verify-pipeline.sh

# drive attack traffic and watch the detections light up
scripts/generate-attacks.sh all
```

Open Grafana:

```bash
kubectl -n monitoring port-forward svc/kps-grafana 3000:80
# user admin; password:
kubectl -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d
```

## Verification

[`scripts/verify_pipeline.py`](scripts/verify_pipeline.py) checks each hop on
the live cluster (results in `reports/pipeline-checks.tsv`):

| | Check |
|---|---|
| C01 | Prometheus scrapes the API (`up == 1`) |
| C02 | normal usage appears in the security metrics |
| C03 | every alert rule is loaded and healthy |
| C04 | the recording rules return data |
| C05 | every dashboard panel query is valid |
| C06 | Grafana serves the provisioned dashboard |
| C07 | a synthetic alert is routed by Alertmanager to the sink |
| C08 | (`--falco`) Falco is running and wired to the sink |

## CI

[`.github/workflows/project3-security-monitoring.yml`](../.github/workflows/project3-security-monitoring.yml):
a **static** job (promtool check + unit tests, shellcheck, dashboard JSON,
python tests) and a **live e2e** job that stands up the hardened cluster, the
app and the whole monitoring stack on the runner and runs
`verify-pipeline.sh`. **`P3 / Pipeline gate`** fails the build unless every
pipeline check passed (fail closed), and `main` requires it.

## Layout

```
helm/          kube-prometheus-stack + falco values (sized for a laptop)
rules/         detection + recording rules; tests/ = promtool unit tests
dashboards/    Grafana security dashboard (auto-provisioned)
manifests/     namespaces, ServiceMonitor, alert-sink (+ its NetworkPolicy)
scripts/       monitoring-up, verify-pipeline(.py), generate-attacks, pipeline_gate
docs/          alert runbook
tests/         unit tests for the CI gate
```

## Notes / residual

- Sizes target a single-node kind cluster on ~5 GB. node-exporter is disabled
  (it needs host access the monitoring namespace's `baseline` PSS forbids);
  node-level host metrics aren't part of the detection story.
- Thresholds are low for a quiet lab; [docs/runbook.md](docs/runbook.md#tuning-thresholds)
  covers baselining for real traffic.
- Alertmanager delivers to an in-cluster webhook; wiring a real destination
  (Slack/PagerDuty/SIEM) is a receiver config change.
