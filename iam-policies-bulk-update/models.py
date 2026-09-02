"""Domain models for Core LZ IAM policy bulk updates."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PolicySnapshot:
    """Current live OCI policy state used for preview and concurrency checks."""

    id: str
    name: str
    compartment_id: str
    lifecycle_state: str
    statements: list[str]
    freeform_tags: dict[str, str]
    etag: str | None
    version_date: str | None = None
    defined_tags: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class StatementChange:
    """One proposed or rejected statement transformation."""

    index: int
    original: str
    proposed: str
    error: str | None = None


@dataclass(frozen=True)
class PrincipalReference:
    """One named policy principal that must exist in the target Identity Domain."""

    principal_type: str
    name: str
    statement_index: int


@dataclass
class PolicyProposal:
    """Original and proposed state for one discovered policy."""

    snapshot: PolicySnapshot
    proposed_statements: list[str]
    proposed_freeform_tags: dict[str, str]
    changes: list[StatementChange] = field(default_factory=list)
    unparseable: list[StatementChange] = field(default_factory=list)
    principal_references: list[PrincipalReference] = field(default_factory=list)
    status: str = "previewed"
    error: str | None = None
    etag_after: str | None = None

    @property
    def changed(self) -> bool:
        """Return whether this policy has at least one statement rewrite."""
        return bool(self.changes)
