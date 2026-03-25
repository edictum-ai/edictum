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
    findings: tuple[ScanFinding, ...]
    result: SkillScanResult


def classify_risk(result: SkillScanResult) -> RiskClassification:
    """Classify a scan result into a risk tier with findings.

    Tier precedence: CRITICAL > HIGH > MEDIUM > CLEAN.
    A skill is classified at its highest-severity finding.
    """
    findings: list[ScanFinding] = []

    # Gather all features for cross-block analysis
    has_pipe_to_shell = False
    has_public_ip = False
    public_ips: list[str] = []
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
    has_high_entropy = False
    has_password_archive = False
    high_external_domains = False

    for cb in result.code_blocks:
        line = cb.line_range[0] if cb.line_range else None

        # Pipe-to-shell
        if cb.pipe_to_shell:
            has_pipe_to_shell = True
            findings.append(
                ScanFinding(
                    message="pipe to shell detected",
                    line=line,
                )
            )

        # IP addresses — check for public IPs
        for ip in cb.ip_addresses_found:
            if not is_private_ip(ip):
                has_public_ip = True
                public_ips.append(ip)
                findings.append(
                    ScanFinding(
                        message=f"public IP address: {ip}",
                        line=line,
                    )
                )

        # Reverse shell patterns
        for cmd in cb.dangerous_commands:
            if cmd in REVERSE_SHELL_LABELS:
                has_reverse_shell = True
                findings.append(
                    ScanFinding(
                        message=f"reverse shell pattern: {cmd}",
                        line=line,
                    )
                )

        # Exfil domains
        for domain in cb.exfil_domains:
            has_exfil_domain = True
            findings.append(
                ScanFinding(
                    message=f"exfiltration domain: {domain}",
                    line=line,
                )
            )

        # Credential paths
        for cred in cb.credential_paths:
            has_credential_access = True
            findings.append(
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
                    findings.append(
                        ScanFinding(
                            message=f"base64 payload decodes to shell command ({blob.dangerous_pattern})",
                            line=line,
                        )
                    )
                else:
                    has_b64_shell = True
                    findings.append(
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
                findings.append(ScanFinding(message=f"dangerous command: {cmd}", line=line))
            elif cmd == "sudo_usage":
                has_sudo = True
                findings.append(ScanFinding(message="sudo usage", line=line))
            elif cmd == "chmod_dangerous":
                has_chmod_dangerous = True
                findings.append(ScanFinding(message="chmod 777 or setuid", line=line))
            elif cmd == "dd_device_write":
                has_dd_device = True
                findings.append(ScanFinding(message="dd write to device", line=line))
            elif cmd in ("hex_shellcode", "js_char_construction", "base64_decode_runtime"):
                has_obfuscation = True
                findings.append(ScanFinding(message=f"obfuscation: {cmd}", line=line))
            elif cmd in ("ssh_key_access", "shadow_access"):
                has_credential_access = True
                findings.append(ScanFinding(message=f"credential-adjacent access: {cmd}", line=line))
            elif cmd == "passwd_access":
                findings.append(ScanFinding(message="passwd command usage", line=line))
            elif cmd == "exfiltration_keyword":
                has_exfil_domain = True
                findings.append(ScanFinding(message="exfiltration keyword detected", line=line))
            else:
                # Generic dangerous command
                findings.append(ScanFinding(message=f"dangerous command: {cmd}", line=line))

        # Obfuscation signals
        for sig in cb.obfuscation_signals:
            has_obfuscation = True
            findings.append(
                ScanFinding(
                    message=f"obfuscation signal: {sig}",
                    line=line,
                )
            )

        # High entropy
        if cb.entropy_score >= HIGH_ENTROPY_THRESHOLD:
            has_high_entropy = True
            findings.append(
                ScanFinding(
                    message=f"high entropy code block ({cb.entropy_score:.1f} bits/char)",
                    line=line,
                )
            )

        # Password-protected archives
        if cb.password_protected_archives:
            has_password_archive = True
            findings.append(
                ScanFinding(
                    message="password-protected archive reference",
                    line=line,
                )
            )

    # External domain count
    if result.risk_signals.external_domain_count > 5:
        high_external_domains = True
        findings.append(
            ScanFinding(
                message=f"unusual number of external domains ({result.risk_signals.external_domain_count})",
            )
        )

    # No contracts (always reported as informational)
    if result.risk_signals.no_contracts:
        findings.append(ScanFinding(message="no contracts.yaml"))

    # Deduplicate findings by message
    seen: set[str] = set()
    unique_findings: list[ScanFinding] = []
    for f in findings:
        key = f"{f.message}:{f.line}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # --- TIER CLASSIFICATION ---

    # CRITICAL: never legitimate, immediate action required
    if has_dangerous_b64_shell:
        # base64 blob decodes to shell command with dangerous pattern
        return RiskClassification(RiskLevel.CRITICAL, tuple(unique_findings), result)

    if has_pipe_to_shell and has_public_ip:
        # pipe-to-shell + raw IP address (non-RFC1918)
        return RiskClassification(RiskLevel.CRITICAL, tuple(unique_findings), result)

    if has_reverse_shell:
        # reverse shell patterns
        return RiskClassification(RiskLevel.CRITICAL, tuple(unique_findings), result)

    if has_credential_access and has_exfil_domain:
        # credential path access + exfil domain in same skill
        return RiskClassification(RiskLevel.CRITICAL, tuple(unique_findings), result)

    # HIGH: likely dangerous, review required
    if has_exfil_domain:
        return RiskClassification(RiskLevel.HIGH, tuple(unique_findings), result)

    if has_credential_access:
        return RiskClassification(RiskLevel.HIGH, tuple(unique_findings), result)

    if has_eval_exec or has_sudo or has_chmod_dangerous or has_dd_device:
        return RiskClassification(RiskLevel.HIGH, tuple(unique_findings), result)

    if has_b64_shell:
        # base64 decodes to shell command (without dangerous pattern)
        return RiskClassification(RiskLevel.HIGH, tuple(unique_findings), result)

    if has_obfuscation:
        return RiskClassification(RiskLevel.HIGH, tuple(unique_findings), result)

    # MEDIUM: suspicious, worth reviewing
    if has_pipe_to_shell:
        return RiskClassification(RiskLevel.MEDIUM, tuple(unique_findings), result)

    if has_high_entropy:
        return RiskClassification(RiskLevel.MEDIUM, tuple(unique_findings), result)

    if has_password_archive:
        return RiskClassification(RiskLevel.MEDIUM, tuple(unique_findings), result)

    if high_external_domains:
        return RiskClassification(RiskLevel.MEDIUM, tuple(unique_findings), result)

    # CLEAN: no actionable findings (may still have "no contracts.yaml" informational)
    return RiskClassification(RiskLevel.CLEAN, tuple(unique_findings), result)
