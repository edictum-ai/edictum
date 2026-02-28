# Audit and Observability

Every contract evaluation in Edictum produces an `AuditEvent`. Audit sinks consume
these events and route them to local storage, while OpenTelemetry integration
enables routing enforcement spans to any observability backend.

## When to use this

Read this when you need to configure where audit events go. It covers the two built-in sinks (`StdoutAuditSink` for development, `FileAuditSink` for persistent JSONL logs), the `RedactionPolicy` for scrubbing secrets from audit records, and the `AuditSink` protocol for routing events to custom destinations. For production observability with span-level metrics and dashboards, see [Telemetry reference](telemetry.md) and the [Observability guide](../guides/observability.md).

---

## The AuditSink Protocol

Any class that implements the `AuditSink` protocol can receive audit events. The
protocol requires a single async method:

```python
from edictum.audit import AuditSink

class MyCustomSink:
    async def emit(self, event: AuditEvent) -> None:
        # process the event
        ...
```

Edictum checks conformance at runtime via `@runtime_checkable`, so there is no need
to inherit from a base class. Implement `emit` and you are done.

Register a sink when constructing your `Edictum` instance:

```python
from edictum import Edictum
from edictum.audit import FileAuditSink

guard = Edictum(
    audit_sink=FileAuditSink("/var/log/edictum/events.jsonl"),
)
```

You can also pass a list of sinks — they are automatically wrapped in a
`CompositeSink`:

```python
from edictum.audit import StdoutAuditSink, FileAuditSink

guard = Edictum(
    audit_sink=[StdoutAuditSink(), FileAuditSink("audit.jsonl")],
)
```

If no `audit_sink` is provided, a `StdoutAuditSink` is used by default.

---

## AuditEvent Fields

Every audit event contains the following fields:

### Identity

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `str` | Event schema version (currently `"0.3.0"`) |
| `timestamp` | `datetime` | UTC timestamp of the event |
| `run_id` | `str` | Unique ID for the agent run |
| `call_id` | `str` | Unique ID for this specific tool call |
| `call_index` | `int` | Sequential call number within the run |
| `parent_call_id` | `str \| None` | Parent call ID for nested invocations |

### Tool

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | `str` | Name of the tool being called |
| `tool_args` | `dict` | Arguments passed to the tool |
| `side_effect` | `str` | Side-effect classification: `pure`, `read`, `write`, `irreversible` |
| `environment` | `str` | Deployment environment (e.g. `production`, `staging`) |

### Principal

| Field | Type | Description |
|-------|------|-------------|
| `principal` | `dict \| None` | Identity context: `user_id`, `service_id`, `org_id`, `role`, `ticket_ref`, `claims` |

### Enforcement Decision

| Field | Type | Description |
|-------|------|-------------|
| `action` | `AuditAction` | One of: `call_denied`, `call_would_deny`, `call_allowed`, `call_executed`, `call_failed`, `postcondition_warning` |
| `decision_source` | `str \| None` | What produced the decision: `hook`, `precondition`, `session_contract`, `attempt_limit`, `operation_limit` |
| `decision_name` | `str \| None` | Name of the specific hook or contract |
| `reason` | `str \| None` | Human-readable denial reason |
| `hooks_evaluated` | `list[dict]` | Each hook with its name, result, and reason |
| `contracts_evaluated` | `list[dict]` | Each contract with name, type, passed, and message |

### Execution

| Field | Type | Description |
|-------|------|-------------|
| `tool_success` | `bool \| None` | Whether the tool call succeeded (set after execution) |
| `postconditions_passed` | `bool \| None` | Whether all postconditions passed |
| `duration_ms` | `int` | Tool execution time in milliseconds |
| `error` | `str \| None` | Error message if the tool failed |
| `result_summary` | `str \| None` | Truncated summary of the tool result |

### Counters

| Field | Type | Description |
|-------|------|-------------|
| `session_attempt_count` | `int` | Total attempts in this session (including denials) |
| `session_execution_count` | `int` | Total executions in this session |

### Policy

| Field | Type | Description |
|-------|------|-------------|
| `policy_version` | `str \| None` | SHA-256 hash of the YAML contract file |
| `policy_error` | `bool` | `True` if there was an error loading contracts |
| `mode` | `str` | `enforce` or `observe` |

---

## Built-in Sinks

### StdoutAuditSink

Prints each event as a single JSON line to stdout. Useful for development and for
piping into log aggregators.

```python
from edictum.audit import StdoutAuditSink, RedactionPolicy

sink = StdoutAuditSink(redaction=RedactionPolicy())
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `redaction` | `RedactionPolicy \| None` | `None` | Redaction policy. When `None`, a default `RedactionPolicy()` is created internally. |

### FileAuditSink

Appends each event as a JSON line to a file. Creates the file if it does not exist.
Suitable for local audit logs and offline analysis.

```python
from edictum.audit import FileAuditSink, RedactionPolicy

sink = FileAuditSink(
    path="/var/log/edictum/events.jsonl",
    redaction=RedactionPolicy(),
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `str \| Path` | (required) | File path for the JSONL output |
| `redaction` | `RedactionPolicy \| None` | `None` | Redaction policy. When `None`, a default `RedactionPolicy()` is created internally. |

### CompositeSink

Fan-out sink that emits every event to multiple sinks sequentially. Useful when
you need both terminal output and a persistent log file, or any combination of
sinks.

```python
from edictum.audit import CompositeSink, StdoutAuditSink, FileAuditSink

sink = CompositeSink([
    StdoutAuditSink(),
    FileAuditSink("/var/log/edictum/events.jsonl"),
])
```

The `Edictum` constructor also accepts a list of sinks directly — it auto-wraps
them in a `CompositeSink`:

```python
from edictum import Edictum
from edictum.audit import StdoutAuditSink, FileAuditSink

guard = Edictum(
    audit_sink=[
        StdoutAuditSink(),
        FileAuditSink("audit.jsonl"),
    ],
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sinks` | `list[AuditSink]` | (required) | One or more sinks to emit to, in order |

Sinks are called in order. If a sink raises, the exception propagates and
subsequent sinks do not receive the event.

#### When to use CompositeSink

| Scenario | Sinks | Who benefits |
|----------|-------|--------------|
| **Dev debugging + persistent audit trail** | `StdoutAuditSink` + `FileAuditSink` | Developer debugging locally — real-time terminal output plus a `.jsonl` file for later analysis |
| **Multi-destination compliance** | `FileAuditSink` + custom sink | Platform team — file for regulatory retention plus a custom sink pushing to an internal dashboard |
| **Gradual migration** | `StdoutAuditSink` + new sink | Anyone migrating — keep existing stdout while adding a new destination, without changing constructor code |
| **Custom sink stacking** | `FileAuditSink` + `KafkaAuditSink` | Compliance — redundant audit trails from a one-liner, each sink independently processes the same events |

CompositeSink is about the structured event log, not observability traces. OTel
spans operate independently and are complementary — use both in production.

### ServerAuditSink (edictum[server])

Batches audit events and sends them to the edictum-server via HTTP. Events are
buffered in memory and flushed when the batch is full or after a timer interval.

```bash
pip install edictum[server]
```

```python
from edictum.server import EdictumServerClient, ServerAuditSink

client = EdictumServerClient(
    "https://edictum.example.com",
    api_key="...",
    agent_id="my-agent",
    env="production",
    bundle_name="devops-agent",
)
sink = ServerAuditSink(client, batch_size=50, flush_interval=5.0)

guard = Edictum(audit_sink=sink)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client` | `EdictumServerClient` | (required) | Configured server client |
| `batch_size` | `int` | `50` | Flush when this many events are buffered |
| `flush_interval` | `float` | `5.0` | Seconds between automatic flushes |

Events are mapped to the server's ingest format (`POST /api/v1/events`) with
`call_id`, `agent_id`, `tool_name`, `verdict`, `mode`, `timestamp`, and a
`payload` dict containing the full enforcement context including `bundle_name`
and `environment` (falls back to the client's `env` if not set on the event).
If a flush fails, events are retained in the buffer for the next attempt.

Call `await sink.close()` to flush remaining events and stop the background timer.

---

### OpenTelemetry Span Emission

For production observability, Edictum emits `edictum.*` spans for every enforcement
decision via OpenTelemetry. These spans can be routed to any OTel-compatible
backend -- Datadog, Splunk, Grafana, Jaeger, or any service that accepts OTLP.

```bash
pip install edictum[otel]
```

#### Programmatic Configuration

```python
from edictum.otel import configure_otel

configure_otel(
    service_name="my-agent",
    endpoint="http://localhost:4317",
    protocol="grpc",  # or "http"
    resource_attributes={"deployment.environment": "production"},
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `service_name` | `str` | `"edictum-agent"` | OTel service name resource attribute |
| `endpoint` | `str` | `"http://localhost:4317"` | OTLP collector endpoint |
| `protocol` | `str` | `"grpc"` | Transport protocol: `"grpc"` or `"http"` |
| `resource_attributes` | `dict \| None` | `None` | Additional OTel resource attributes |
| `edictum_version` | `str \| None` | `None` | Edictum version tag |

Standard OTel environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`) override the programmatic
values when set.

#### YAML Configuration

The `observability` block in a contract bundle configures OTel alongside the
local sinks:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: my-policy

observability:
  otel:
    enabled: true
    endpoint: "http://localhost:4317"
    protocol: grpc
    service_name: my-agent
    resource_attributes:
      deployment.environment: production
  stdout: true
  file: /var/log/edictum/events.jsonl

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets]
```

#### Routing to Specific Backends

Edictum emits standard OTLP spans. Use an OTel Collector to route them to any
backend:

**Datadog**: Point the OTel Collector at the Datadog Agent or use the Datadog
exporter in the collector config. Enforcement spans appear in Datadog APM traces.

**Splunk**: Use the Splunk HEC exporter in the OTel Collector config. Spans
arrive in Splunk Observability Cloud with all `edictum.*` attributes intact.

**Grafana / Tempo**: Send OTLP directly to Grafana Tempo or via the OTel
Collector. Enforcement spans appear alongside application traces.

**Jaeger**: Point the OTLP endpoint at a Jaeger collector. No additional
configuration needed.

#### Graceful Degradation

If `opentelemetry` is not installed, all OTel instrumentation degrades to a
silent no-op. No exceptions are raised and there is no performance cost beyond
a single boolean check per call. The local sinks (`StdoutAuditSink`,
`FileAuditSink`) continue to work independently of OTel availability.

---

## Redaction Policy

All sinks support automatic redaction of sensitive data via `RedactionPolicy`. If
no explicit policy is provided, `StdoutAuditSink` and `FileAuditSink` create a
default policy automatically. OTel span attributes are emitted after redaction
is applied to the underlying `AuditEvent`.

### Sensitive Key Detection

Keys are normalized to lowercase and matched against a built-in set:

`password`, `secret`, `token`, `api_key`, `apikey`, `api-key`, `authorization`,
`auth`, `credentials`, `private_key`, `privatekey`, `access_token`,
`refresh_token`, `client_secret`, `connection_string`, `database_url`,
`db_password`, `ssh_key`, `passphrase`

Additionally, any key containing `token`, `key`, `secret`, `password`, or
`credential` as a substring is treated as sensitive.

### Secret Value Pattern Detection

Values are checked against patterns for common secret formats, regardless of the
key name:

| Pattern | Example |
|---------|---------|
| `sk-*` | OpenAI API keys |
| `AKIA*` | AWS access key IDs |
| `eyJ*` | JWT tokens |
| `ghp_*` | GitHub personal access tokens |
| `xox[bpas]-*` | Slack tokens |

### Bash Command Redaction

Bash commands in `tool_args` are scrubbed for inline secrets:

- `export SECRET_KEY=abc123` becomes `export SECRET_KEY=[REDACTED]`
- `-p mypassword` becomes `-p [REDACTED]`
- `https://user:pass@host` becomes `https://user:[REDACTED]@host`

### Payload Size Cap

Payloads exceeding 32 KB are truncated. The `tool_args` and `result_summary` fields
are replaced with a marker indicating the cap was hit. This prevents audit sinks from
dropping events due to oversized payloads.

### Custom Redaction

```python
from edictum.audit import RedactionPolicy

policy = RedactionPolicy(
    sensitive_keys={"my_custom_key", "internal_token"},  # merged with defaults (union)
    custom_patterns=[
        (r"(MY_PREFIX_)\S+", r"\1[REDACTED]"),           # custom regex substitutions
    ],
    detect_secret_values=True,                            # enable/disable value pattern detection
)
```

---

## Custom Sinks

Implement the `AuditSink` protocol to route events to any destination:

```python
import json
from edictum.audit import AuditEvent, RedactionPolicy

class KafkaAuditSink:
    """Send audit events to a Kafka topic."""

    def __init__(self, producer, topic: str, redaction: RedactionPolicy | None = None):
        self._producer = producer
        self._topic = topic
        self._redaction = redaction or RedactionPolicy()

    async def emit(self, event: AuditEvent) -> None:
        from dataclasses import asdict
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        data = self._redaction.cap_payload(data)
        await self._producer.send(
            self._topic,
            json.dumps(data, default=str).encode(),
        )
```

Then register it:

```python
guard = Edictum(
    audit_sink=KafkaAuditSink(producer, "edictum-events"),
)
```

The `AuditSink` protocol is `@runtime_checkable`, so Edictum validates your
sink at registration time. If `emit` is missing or has the wrong signature,
you get an immediate `TypeError` rather than a silent failure at event time.
