"""Core data types: capabilities, findings and attack steps."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Capability:
    """Something an attacker can have or do. A capability with impact > 0 is a goal."""

    key: str
    label: str
    impact: int = 0

    @property
    def is_goal(self) -> bool:
        return self.impact > 0


_CAPS = [
    # Starting positions (assumptions about the attacker)
    Capability("internet", "Reach the app over the network"),
    Capability("source_read", "Read the source code (public repo, leak or insider)"),
    # Footholds
    Capability("db_creds", "Database credentials"),
    Capability("jwt_secret", "The app's token-signing secret"),
    Capability("cloud_creds", "Cloud provider access keys"),
    Capability("api_token", "A service token or account password"),
    Capability("server_key", "A private key for a server or service"),
    Capability("db_network", "Network access to the database port"),
    Capability("session_forge", "Forge a valid session for any user"),
    Capability("container_root", "Root inside the app container"),
    # Goals (what the business actually loses)
    Capability("host_root", "Root on the host server", 10),
    Capability("cloud_takeover", "Control of the cloud account", 10),
    Capability("db_write", "Modify or wipe the database", 9),
    Capability("rce", "Run arbitrary code in the app", 8),
    Capability("db_read", "Dump the database", 8),
    Capability("admin_access", "Full admin access to the app", 7),
    Capability("third_party_abuse", "Abuse a connected service or account", 6),
    Capability("user_data_theft", "Steal signed-in users' data from another site", 5),
    Capability("info_leak", "Leak internal details (stack traces, settings)", 3),
]
CAPABILITIES: Dict[str, Capability] = {c.key: c for c in _CAPS}
START_CAPABILITIES = ("internet", "source_read")


def cap_label(key: str) -> str:
    cap = CAPABILITIES.get(key)
    return cap.label if cap else key


def cap_impact(key: str) -> int:
    cap = CAPABILITIES.get(key)
    return cap.impact if cap else 0


@dataclass
class FileContext:
    """A file being scanned."""

    path: str  # relative, forward slashes
    abspath: str
    text: str
    kind: str
    _lines: Optional[List[str]] = field(default=None, repr=False)

    @property
    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    @property
    def name(self) -> str:
        return os.path.basename(self.path)


@dataclass(frozen=True)
class Finding:
    """One weakness found in one place, with what it needs and what it gives an attacker."""

    rule: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    fix: str
    requires: FrozenSet[str]
    grants: FrozenSet[str]
    confidence: float = 0.8

    @property
    def id(self) -> str:
        return f"{self.rule}:{self.file}:{self.line}"

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "fix": self.fix,
            "requires": sorted(self.requires),
            "grants": sorted(self.grants),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class Step:
    """An edge in the attack graph: either a finding in the code or a generic attacker technique."""

    id: str
    kind: str  # "finding" or "technique"
    title: str
    requires: FrozenSet[str]
    grants: FrozenSet[str]
    confidence: float
    finding: Optional[Finding] = None

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "requires": sorted(self.requires),
            "grants": sorted(self.grants),
            "confidence": self.confidence,
        }
        if self.finding is not None:
            f = self.finding
            d.update(rule=f.rule, file=f.file, line=f.line, severity=f.severity, fix=f.fix)
        return d
