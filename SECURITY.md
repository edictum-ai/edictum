# Security Policy

## Reporting A Vulnerability

If you find a vulnerability in Edictum, report it privately.

**Email:** [security@edictum.ai](mailto:security@edictum.ai)

Do not open a public GitHub issue for vulnerability reports.

## Response Timeline

| Stage | SLA |
| --- | --- |
| Acknowledgment | 48 hours |
| Triage and severity assessment | 7 days |
| Fix for critical or high severity issues | Best effort, typically within 30 days |

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | Fixes only on a case-by-case basis |

## Scope

This policy covers:

- `edictum`: core Python library in this repo
- `edictum[gate]`: coding assistant runtime enforcement
- `edictum-console`: self-hostable control plane and review UI

## Safe Harbor

Good-faith security research is authorized. We will not pursue legal action against researchers who:

- avoid privacy violations, data destruction, and service disruption
- only use accounts they own or have explicit permission to test
- report vulnerabilities promptly with enough detail to reproduce
- avoid public disclosure before a fix is available

## Enforcement Model

Edictum's core runtime is built around a few simple rules:

- No LLM in the enforcement path. Rules match tool names, tool arguments, output, session state, and workflow state with deterministic code.
- Fail closed. Rule parse errors, type mismatches, missing fields, and unhandled pipeline errors turn into block decisions.
- Core stays small. The standalone library has no required third-party runtime dependencies.
- Secret redaction happens before data is written to a decision log destination or surfaced in a block message.

For more detail on threat boundaries and adversarial coverage, see [docs.edictum.ai](https://docs.edictum.ai).
