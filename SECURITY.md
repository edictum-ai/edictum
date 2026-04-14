# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Edictum, please report it responsibly.

**Email:** [security@edictum.ai](mailto:security@edictum.ai)

**Do not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

| Stage | SLA |
|-------|-----|
| Acknowledgment | 48 hours |
| Triage and severity assessment | 7 days |
| Fix for critical/high severity | Best effort, typically within 30 days |

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Security fixes only, on a case-by-case basis |

## Scope

This policy covers:

- **edictum** -- core Python library (this repo, [PyPI](https://pypi.org/project/edictum/))
- **edictum gate** -- coding assistant governance layer (`pip install edictum[gate]`)
- **edictum-api** -- hosted control-plane API ([GitHub](https://github.com/edictum-ai/edictum-api))
- **edictum-app** -- hosted control-plane frontend ([GitHub](https://github.com/edictum-ai/edictum-app))

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, or service disruption
- Only interact with accounts they own or with explicit permission
- Report vulnerabilities promptly and provide sufficient detail for reproduction
- Do not publicly disclose the vulnerability before a fix is available

## Security Design

Edictum's core enforcement is designed around these principles:

- **No LLM in the enforcement path.** Contracts evaluate tool names and arguments against YAML conditions using deterministic pattern matching. The evaluation pipeline never calls an LLM.
- **Fail closed.** Contract parse errors, type mismatches, missing fields, and unhandled exceptions in the pipeline all result in deny decisions. The agent never silently passes when the system encounters an error.
- **Zero runtime dependencies.** The core library has no third-party dependencies, minimizing supply chain attack surface.
- **Automatic secret redaction.** API keys, tokens, passwords, and connection strings are redacted from audit events and denial messages before they reach any sink.

For details on Edictum's security model, threat boundaries, and adversarial test coverage, see [docs.edictum.ai](https://docs.edictum.ai).
