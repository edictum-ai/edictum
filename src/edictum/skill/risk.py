"""Risk classification for scanned skills.

Deterministic tiering: CRITICAL > HIGH > MEDIUM > CLEAN.
Each tier has clear, auditable criteria based on extracted features.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from edictum.skill.patterns import HIGH_ENTROPY_THRESHOLD, REVERSE_SHELL_LABELS, is_private_ip
from edictum.skill.scanner import SkillScanResult


class RiskLevel(enum.Enum):
    """Severity tier for a scanned skill."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    CLEAN = "CLEAN"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return _RISK_ORDER[self] >= _RISK_ORDER[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return _RISK_ORDER[self] > _RISK_ORDER[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return _RISK_ORDER[self] <= _RISK_ORDER[other]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return _RISK_ORDER[self] < _RISK_ORDER[other]


_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.CLEAN: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


@dataclass(frozen=True)
class ScanFinding:
    """A single security finding within a skill."""

    message: str
    line: int | None = None  # line number in SKILL.md, if applicable


@dataclass(frozen=True)
class RiskClassification:
    """Risk classification for a scanned skill."""

    level: RiskLevel
    violations: tuple[ScanFinding, ...]
    result: SkillScanResult


def classify_risk(result: SkillScanResult) -> RiskClassification:
    """Classify a scan result into a risk tier with violations.

    Tier precedence: CRITICAL > HIGH > MEDIUM > CLEAN.
    A skill is classified at its highest-severity finding.
    """
    violations: list[ScanFinding] = []

    # Gather all features for cross-block analysis
    has_pipe_to_shell = False
    has_public_ip = False
    has_reverse_shell = False
    has_exfil_domain = False
    has_credential_access = False
    has_dangerous_b64_shell = False
    has_b64_shell = False
    has_eval_exec = False
    has_sudo = False
    has_chmod_dangerous = False
    has_dd_device = False
    has_obfuscation = False
    has_dangerous_command = False
    has_high_entropy = False
    has_password_archive = False
    high_external_domains = False

    for cb in result.code_blocks:
        line = cb.line_range[0] if cb.line_range else None

        # Pipe-to-shell
        if cb.pipe_to_shell:
            has_pipe_to_shell = True
            violations.append(
                ScanFinding(
                    message="pipe to shell detected",
                    line=line,
                )
            )

        # IP addresses — check for public IPs
        for ip in cb.ip_addresses_found:
            if not is_private_ip(ip):
                has_public_ip = True
                violations.append(
                    ScanFinding(
                        message=f"public IP address: {ip}",
                        line=line,
                    )
                )

        # Reverse shell patterns
        for cmd in cb.dangerous_commands:
            if cmd in REVERSE_SHELL_LABELS:
                has_reverse_shell = True
                violations.append(
                    ScanFinding(
                        message=f"reverse shell pattern: {cmd}",
                        line=line,
                    )
                )

        # Exfil domains
        for domain in cb.exfil_domains:
            has_exfil_domain = True
            violations.append(
                ScanFinding(
                    message=f"exfiltration domain: {domain}",
                    line=line,
                )
            )

        # Credential paths
        for cred in cb.credential_paths:
            has_credential_access = True
            violations.append(
                ScanFinding(
                    message=f"credential path access: {cred}",
                    line=line,
                )
            )

        # Base64 blobs with shell commands
        for blob in cb.base64_blobs:
            if blob.classification == "shell_command":
                if blob.dangerous_pattern:
                    has_dangerous_b64_shell = True
                    violations.append(
                        ScanFinding(
                            message=f"base64 payload decodes to shell command ({blob.dangerous_pattern})",
                            line=line,
                        )
                    )
                else:
                    has_b64_shell = True
                    violations.append(
                        ScanFinding(
                            message="base64 payload decodes to shell command",
                            line=line,
                        )
                    )

        # Dangerous commands (non-reverse-shell)
        for cmd in cb.dangerous_commands:
            if cmd in REVERSE_SHELL_LABELS:
                continue  # already handled above
            if cmd in ("eval_exec", "python_shell_exec"):
                has_eval_exec = True
                violations.append(ScanFinding(message=f"dangerous command: {cmd}", line=line))
            elif cmd == "sudo_usage":
                has_sudo = True
                violations.append(ScanFinding(message="sudo usage", line=line))
            elif cmd == "chmod_dangerous":
                has_chmod_dangerous = True
                violations.append(ScanFinding(message="chmod 777 or setuid", line=line))
            elif cmd == "dd_device_write":
                has_dd_device = True
                violations.append(ScanFinding(message="dd write to device", line=line))
            elif cmd in ("hex_shellcode", "js_char_construction", "base64_decode_runtime"):
                has_obfuscation = True
                violations.append(ScanFinding(message=f"obfuscation: {cmd}", line=line))
            elif cmd in ("ssh_key_access", "shadow_access"):
                has_credential_access = True
                violations.append(ScanFinding(message=f"credential-adjacent access: {cmd}", line=line))
            elif cmd == "passwd_access":
                has_credential_access = True
                violations.append(ScanFinding(message="passwd command usage", line=line))
            elif cmd == "exfiltration_keyword":
                # Keyword match only (no actual domain) — route to dangerous_command
                # to avoid false CRITICAL via credential+exfil when there's no real domain
                has_dangerous_command = True
                violations.append(ScanFinding(message="exfiltration keyword detected", line=line))
            elif cmd in ("curl_pipe_shell", "wget_pipe_shell"):
                # These labels also match PIPE_TO_SHELL_RE independently via
                # cb.pipe_to_shell, but set the flag here too for defense-in-depth
                has_pipe_to_shell = True
                violations.append(ScanFinding(message=f"dangerous command: {cmd}", line=line))
            else:
                # Catch-all: mkfs_format, destructive_rm_root, etc.
                has_dangerous_command = True
                violations.append(ScanFinding(message=f"dangerous command: {cmd}", line=line))

        # Obfuscation signals
        for sig in cb.obfuscation_signals:
            has_obfuscation = True
            violations.append(
                ScanFinding(
                    message=f"obfuscation signal: {sig}",
                    line=line,
                )
            )

        # High entropy
        if cb.entropy_score >= HIGH_ENTROPY_THRESHOLD:
            has_high_entropy = True
            violations.append(
                ScanFinding(
                    message=f"high entropy code block ({cb.entropy_score:.1f} bits/char)",
                    line=line,
                )
            )

        # Password-protected archives
        if cb.password_protected_archives:
            has_password_archive = True
            violations.append(
                ScanFinding(
                    message="password-protected archive reference",
                    line=line,
                )
            )

    # External domain count
    if result.risk_signals.external_domain_count > 5:
        high_external_domains = True
        violations.append(
            ScanFinding(
                message=f"unusual number of external domains ({result.risk_signals.external_domain_count})",
            )
        )

    # Truncation warning — analysis was incomplete, could hide payloads
    has_truncation = False
    if result.truncated:
        has_truncation = True
        violations.append(ScanFinding(message="analysis truncated: code blocks exceeded limit (potential evasion)"))

    # No rules (always reported as informational)
    if result.risk_signals.no_contracts:
        violations.append(ScanFinding(message="no rules.yaml"))

    # Deduplicate violations by message
    seen: set[str] = set()
    unique_findings: list[ScanFinding] = []
    for f in violations:
        key = f"{f.message}:{f.line}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # --- TIER CLASSIFICATION (highest match wins) ---
    fzn = tuple(unique_findings)

    is_critical = (
        has_dangerous_b64_shell
        or (has_pipe_to_shell and has_public_ip)
        or has_reverse_shell
        or (has_credential_access and has_exfil_domain)
    )
    if is_critical:
        return RiskClassification(RiskLevel.CRITICAL, fzn, result)

    is_high = (
        has_exfil_domain
        or has_credential_access
        or has_eval_exec
        or has_sudo
        or has_chmod_dangerous
        or has_dd_device
        or has_dangerous_command
        or has_b64_shell
        or has_obfuscation
    )
    if is_high:
        return RiskClassification(RiskLevel.HIGH, fzn, result)

    is_medium = has_pipe_to_shell or has_high_entropy or has_password_archive or high_external_domains or has_truncation
    if is_medium:
        return RiskClassification(RiskLevel.MEDIUM, fzn, result)

    return RiskClassification(RiskLevel.CLEAN, fzn, result)
