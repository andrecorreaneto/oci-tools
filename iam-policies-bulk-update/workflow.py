"""Preview, audit, and update workflow for Core LZ IAM policies."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from typing import Callable, TextIO

from discovery import PolicyDiscovery
from models import PolicyProposal, PolicySnapshot, PrincipalReference, StatementChange
from oci_cli import OciCliError
from transform import PolicyStatementTransformer


class PolicyProposalBuilder:
    """Build complete policy proposals from statement-level transformations."""

    MARKER_KEY = "iam-policies-bulk-update"

    def __init__(self, identity_domain_name: str, marker_value: str):
        """Create a proposal builder for one domain and run marker."""
        self.transformer = PolicyStatementTransformer(identity_domain_name)
        self.marker_value = marker_value

    def build(self, snapshot: PolicySnapshot) -> PolicyProposal:
        """Transform every statement while preserving order and parse failures."""
        proposed_statements: list[str] = []
        changes: list[StatementChange] = []
        unparseable: list[StatementChange] = []
        principal_references: list[PrincipalReference] = []
        for index, statement in enumerate(snapshot.statements):
            result = self.transformer.transform(statement)
            proposed_statements.append(result.statement)
            change = StatementChange(index, statement, result.statement, result.error)
            if result.error:
                unparseable.append(change)
            elif result.changed:
                changes.append(change)
            if result.principal_type:
                principal_references.extend(PrincipalReference(result.principal_type, name, index) for name in result.named_principals)
        proposed_tags = dict(snapshot.freeform_tags)
        if changes:
            proposed_tags[self.MARKER_KEY] = self.marker_value
        return PolicyProposal(snapshot, proposed_statements, proposed_tags, changes, unparseable, principal_references, status="previewed" if changes else "unchanged")


class IdentityDomainPrincipalValidator:
    """Report named policy principals that are absent from one Identity Domain."""

    def __init__(self, oci):
        """Create validation around the OCI CLI gateway."""
        self.oci = oci

    def validate(self, endpoint: str, proposals: list[PolicyProposal], identity_domain_profile: str | None) -> dict:
        """Return missing named principals with their associated policies without blocking discovery."""
        references = self._references_by_principal(proposals)
        try:
            existing = self.oci.list_identity_domain_principals(endpoint, identity_domain_profile)
        except OciCliError as error:
            return {"status": "unavailable", "error": str(error), "checked_principals": len(references), "missing_principals": []}
        missing = []
        for (principal_type, name), associations in sorted(references.items()):
            if name not in existing.get(principal_type, set()):
                missing.append({"principal_type": principal_type, "name": name, "policies": associations})
        return {"status": "completed", "checked_principals": len(references), "missing_principals": missing}

    def _references_by_principal(self, proposals: list[PolicyProposal]) -> dict[tuple[str, str], list[dict]]:
        """Group named principal references by type and name for concise audit reporting."""
        references: dict[tuple[str, str], list[dict]] = {}
        for proposal in proposals:
            for reference in proposal.principal_references:
                association = {"policy_id": proposal.snapshot.id, "policy_name": proposal.snapshot.name, "statement_index": reference.statement_index}
                references.setdefault((reference.principal_type, reference.name), []).append(association)
        return references


class PreflightError(RuntimeError):
    """Raised when live policy state changed after preview."""


class PolicyUpdateError(RuntimeError):
    """Raised after the first update or verification failure."""


class PolicyBulkUpdater:
    """Preflight and sequentially update approved policy proposals."""

    def __init__(self, oci, audit_store: "AuditReportStore", output: TextIO):
        """Create an updater around OCI CLI and an audit store."""
        self.oci = oci
        self.audit_store = audit_store
        self.output = output

    def apply(self, proposals: list[PolicyProposal], report: dict) -> bool:
        """Preflight every changing policy before any live update."""
        changing = [proposal for proposal in proposals if proposal.changed]
        for index, proposal in enumerate(changing, 1):
            progress = f"[{index}/{len(changing)}]"
            print(f"{progress} Preflight checking policy {proposal.snapshot.name} ...", file=self.output, flush=True)
            current = self.oci.get_policy(proposal.snapshot.id)
            reason = self._preflight_difference(proposal.snapshot, current)
            if reason:
                proposal.status = "preflight_failed"
                proposal.error = reason
                self.audit_store.refresh(report, proposals, "preflight_failed")
                raise PreflightError(f"{proposal.snapshot.name}: {reason}")
            print(f"{progress} Preflight passed for policy {proposal.snapshot.name}.", file=self.output, flush=True)
        print("Preflight completed. No concurrent changes detected.", file=self.output, flush=True)
        for index, proposal in enumerate(changing):
            progress = f"[{index + 1}/{len(changing)}]"
            try:
                print(f"{progress} Updating policy {proposal.snapshot.name} ...", file=self.output, flush=True)
                self._update_one(proposal, progress)
                self.audit_store.refresh(report, proposals, "applying")
            except Exception as error:
                proposal.status = "failed"
                proposal.error = str(error)
                for untouched in changing[index + 1:]:
                    untouched.status = "untouched"
                self.audit_store.refresh(report, proposals, "failed")
                raise PolicyUpdateError(f"{proposal.snapshot.name}: {error}") from error
        self.audit_store.refresh(report, proposals, "completed")
        print(f"Completed: {len(changing)} policies updated and verified.", file=self.output, flush=True)
        return True

    def _update_one(self, proposal: PolicyProposal, progress: str) -> None:
        """Update and verify one policy using temporary JSON files."""
        with tempfile.TemporaryDirectory(prefix="iam-policies-bulk-update-") as directory:
            statements_path = Path(directory) / "statements.json"
            tags_path = Path(directory) / "freeform-tags.json"
            statements_path.write_text(json.dumps(proposal.proposed_statements), encoding="utf-8")
            tags_path.write_text(json.dumps(proposal.proposed_freeform_tags), encoding="utf-8")
            self.oci.update_policy(proposal.snapshot.id, statements_path, tags_path, proposal.snapshot.etag, proposal.snapshot.version_date)
        print(f"{progress} Verifying policy {proposal.snapshot.name} ...", file=self.output, flush=True)
        current = self.oci.get_policy(proposal.snapshot.id)
        if current.statements != proposal.proposed_statements:
            raise ValueError("post-update statements do not match the proposal")
        if current.freeform_tags != proposal.proposed_freeform_tags:
            raise ValueError("post-update freeform tags do not match the proposal")
        if current.defined_tags != proposal.snapshot.defined_tags:
            raise ValueError("post-update defined tags do not match the proposal")
        if current.version_date != proposal.snapshot.version_date:
            raise ValueError("post-update version date does not match the proposal")
        proposal.status = "updated"
        proposal.etag_after = current.etag
        print(f"{progress} Policy {proposal.snapshot.name} verified.", file=self.output, flush=True)

    def _preflight_difference(self, expected: PolicySnapshot, current: PolicySnapshot) -> str | None:
        """Return the first concurrency or lifecycle mismatch."""
        if expected.lifecycle_state != "ACTIVE" or current.lifecycle_state != "ACTIVE":
            return "policy is not ACTIVE"
        if not expected.etag or not current.etag:
            return "policy ETag is missing"
        if current.etag != expected.etag:
            return "policy ETag changed after preview"
        if current.version_date != expected.version_date:
            return "policy version date changed after preview"
        if current.statements != expected.statements:
            return "policy statements changed after preview"
        if current.freeform_tags != expected.freeform_tags:
            return "policy freeform tags changed after preview"
        if current.defined_tags != expected.defined_tags:
            return "policy defined tags changed after preview"
        return None


class PolicyDomainUpdateApplication:
    """Run discovery and write a reviewable preview report without mutation."""

    def __init__(self, oci, report_dir: Path, output: TextIO, utc_now: Callable[[], datetime], identity_domain_endpoint: str, identity_domain_profile: str | None):
        """Create the preview application around injectable boundaries."""
        self.oci = oci
        self.report_dir = report_dir
        self.output = output
        self.utc_now = utc_now
        self.identity_domain_endpoint = identity_domain_endpoint
        self.identity_domain_profile = identity_domain_profile

    def run(self, tag_namespace: str | None, tag_key: str, tag_value: str, identity_domain_name: str) -> int:
        """Execute one non-mutating discovery run and return its exit code."""
        now = self.utc_now().astimezone(timezone.utc)
        report_timestamp = now.strftime("%Y%m%dT%H%M%SZ")
        marker_timestamp = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        tag_selector = f"{tag_namespace!r}.{tag_key!r}" if tag_namespace else repr(tag_key)
        print(f"Searching for policies tagged {tag_selector} = {tag_value!r} ...", file=self.output, flush=True)
        discovery = PolicyDiscovery(self.oci, lambda message: print(message, file=self.output, flush=True))
        snapshots = discovery.discover(tag_namespace, tag_key, tag_value)
        print(f"Discovery complete: {len(snapshots)} policies selected.", file=self.output, flush=True)
        proposals = [PolicyProposalBuilder(identity_domain_name, marker_timestamp).build(snapshot) for snapshot in snapshots]
        principal_validation = IdentityDomainPrincipalValidator(self.oci).validate(self.identity_domain_endpoint, proposals, self.identity_domain_profile)
        report_path = self.report_dir / f"iam-policies-bulk-update-{report_timestamp}.json"
        audit_store = AuditReportStore(report_path)
        report = audit_store.create({"tag_namespace": tag_namespace, "tag_key": tag_key, "tag_value": tag_value, "resolved_tag_values": discovery.resolved_tag_values, "identity_domain_name": identity_domain_name, "identity_domain_profile": self.identity_domain_profile, "run_timestamp": marker_timestamp}, proposals, principal_validation)
        audit_store.write(report)
        print(f"Audit report written: {report_path}", file=self.output, flush=True)
        summary = report["summary"]
        print(f"Preview summary: {summary['discovered_policies']} policies selected, {summary['changing_policies']} changing, {summary['changed_statements']} statement changes, {summary['unparseable_statements']} unparseable.", file=self.output, flush=True)
        self._print_principal_validation(principal_validation)
        print("WARNING: OUT-OF-BAND OCI UPDATE. A later Terraform apply may revert these changes.", file=self.output, flush=True)
        if not snapshots:
            audit_store.refresh(report, proposals, "no_policies")
            print("No matching policies were selected. No changes made.", file=self.output, flush=True)
            return 2
        if not any(proposal.changed for proposal in proposals):
            audit_store.refresh(report, proposals, "no_changes")
            print("No policy statements require updates. No changes made.", file=self.output, flush=True)
            return 0
        audit_store.refresh(report, proposals, "preview_only")
        print("Preview only. No OCI policies were changed.", file=self.output, flush=True)
        print(f"Apply with: python policy_bulk_update.py --audit-report {str(report_path)!r} --confirm-identity-domain-name {identity_domain_name!r}", file=self.output, flush=True)
        return 0

    def _print_principal_validation(self, validation: dict) -> None:
        """Print one concise non-blocking principal-validation outcome."""
        if validation["status"] == "unavailable":
            print("Identity Domain principal validation unavailable. Review the audit report.", file=self.output, flush=True)
            return
        missing = validation["missing_principals"]
        policy_ids = {association["policy_id"] for principal in missing for association in principal["policies"]}
        print(f"Identity Domain principal validation: {len(missing)} missing principals across {len(policy_ids)} policies.", file=self.output, flush=True)
        if missing:
            print(f"Missing principals: {'; '.join(AuditReportStore.missing_principal_names(validation))}", file=self.output, flush=True)


class PolicyReportApplyApplication:
    """Apply the exact proposals stored in one preview-only audit report."""

    def __init__(self, oci, output: TextIO):
        """Create the apply application around OCI and console output."""
        self.oci = oci
        self.output = output

    def run(self, audit_store: "AuditReportStore", report: dict, proposals: list[PolicyProposal], confirmation: str) -> int:
        """Confirm, preflight, update, and verify the stored proposals."""
        identity_domain_name = report["inputs"]["identity_domain_name"]
        if confirmation != identity_domain_name:
            raise ValueError("confirm_identity_domain_name must exactly match the audit report Identity Domain")
        report["confirmed_at"] = datetime.now(timezone.utc).isoformat()
        changing_count = sum(1 for proposal in proposals if proposal.changed)
        print(f"Loaded preview-only audit report: {audit_store.path}", file=self.output, flush=True)
        print(f"Confirmation accepted. Running preflight for {changing_count} policies ...", file=self.output, flush=True)
        try:
            PolicyBulkUpdater(self.oci, audit_store, self.output).apply(proposals, report)
            return 0
        except PreflightError as error:
            print(f"PREFLIGHT FAILED: {error}", file=self.output, flush=True)
            return 2
        except PolicyUpdateError as error:
            print(f"UPDATE FAILED: {error}", file=self.output, flush=True)
            return 1


class AuditReportStore:
    """Create and atomically persist the pre-update audit/recovery record."""

    SCHEMA_VERSION = 1

    def __init__(self, path: Path):
        """Create a store for one timestamped report path."""
        self.path = path

    def create(self, inputs: dict[str, object], proposals: list[PolicyProposal], principal_validation: dict | None = None) -> dict:
        """Create the complete preview report before confirmation."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "previewed",
            "inputs": dict(inputs),
            "principal_validation": principal_validation or {"status": "not_run", "checked_principals": 0, "missing_principals": []},
            "policies": [self._policy_payload(proposal) for proposal in proposals],
            "summary": self._summary(proposals, principal_validation),
        }

    def create_identity_domain_validation_failure(self, inputs: dict[str, object], error: str, created_at: datetime) -> dict:
        """Create a non-applicable audit record for a failed initial Identity Domain lookup."""
        principal_validation = {"status": "not_run", "checked_principals": 0, "missing_principals": []}
        return {
            "schema_version": self.SCHEMA_VERSION,
            "created_at": created_at.astimezone(timezone.utc).isoformat(),
            "status": "identity_domain_validation_failed",
            "inputs": dict(inputs),
            "identity_domain_validation_error": error,
            "principal_validation": principal_validation,
            "policies": [],
            "summary": self._summary([], principal_validation),
        }

    def write(self, report: dict) -> None:
        """Atomically persist the latest report status."""
        temporary_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_path.replace(self.path)

    def load_preview(self) -> tuple[dict, list[PolicyProposal]]:
        """Load and validate one preview-only report as executable proposals."""
        try:
            report = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"cannot read audit report {self.path}: {error}") from error
        if not isinstance(report, dict) or report.get("schema_version") != self.SCHEMA_VERSION:
            raise ValueError("audit report schema_version is unsupported")
        if report.get("status") != "preview_only":
            raise ValueError("audit report status must be preview_only")
        inputs = report.get("inputs")
        if not isinstance(inputs, dict) or not isinstance(inputs.get("identity_domain_name"), str) or not inputs["identity_domain_name"]:
            raise ValueError("audit report Identity Domain is missing")
        policy_payloads = report.get("policies")
        if not isinstance(policy_payloads, list):
            raise ValueError("audit report policies must be a list")
        proposals = [self._proposal_from_payload(payload) for payload in policy_payloads]
        if not any(proposal.changed for proposal in proposals):
            raise ValueError("audit report contains no changing policies")
        return report, proposals

    def refresh(self, report: dict, proposals: list[PolicyProposal], status: str) -> None:
        """Refresh outcomes and persist the report after a workflow transition."""
        report["status"] = status
        report["policies"] = [self._policy_payload(proposal) for proposal in proposals]
        report["summary"] = self._summary(proposals, report.get("principal_validation"))
        self.write(report)

    def _policy_payload(self, proposal: PolicyProposal) -> dict:
        """Serialize one proposal without losing original recovery data."""
        snapshot = proposal.snapshot
        return {
            "id": snapshot.id,
            "name": snapshot.name,
            "compartment_id": snapshot.compartment_id,
            "lifecycle_state": snapshot.lifecycle_state,
            "etag_before": snapshot.etag,
            "etag_after": proposal.etag_after,
            "version_date": snapshot.version_date,
            "original_statements": list(snapshot.statements),
            "proposed_statements": list(proposal.proposed_statements),
            "original_freeform_tags": dict(snapshot.freeform_tags),
            "proposed_freeform_tags": dict(proposal.proposed_freeform_tags),
            "original_defined_tags": {namespace: dict(tags) for namespace, tags in snapshot.defined_tags.items()},
            "changes": [self._change_payload(change) for change in proposal.changes],
            "unparseable": [self._change_payload(change) for change in proposal.unparseable],
            "principal_references": [self._principal_reference_payload(reference) for reference in proposal.principal_references],
            "status": proposal.status,
            "error": proposal.error,
        }

    def _proposal_from_payload(self, payload: dict) -> PolicyProposal:
        """Reconstruct and validate one reviewed policy proposal."""
        if not isinstance(payload, dict):
            raise ValueError("audit report policy entry must be an object")
        string_fields = ("id", "name", "compartment_id", "lifecycle_state", "etag_before")
        if any(not isinstance(payload.get(field), str) or not payload[field] for field in string_fields):
            raise ValueError("audit report policy metadata is incomplete")
        if "version_date" not in payload or (payload["version_date"] is not None and not isinstance(payload["version_date"], str)):
            raise ValueError("audit report policy version_date is missing or invalid")
        original_statements = self._string_list(payload.get("original_statements"), "original_statements")
        proposed_statements = self._string_list(payload.get("proposed_statements"), "proposed_statements")
        original_tags = self._string_map(payload.get("original_freeform_tags"), "original_freeform_tags")
        proposed_tags = self._string_map(payload.get("proposed_freeform_tags"), "proposed_freeform_tags")
        defined_tags = self._nested_string_map(payload.get("original_defined_tags", {}), "original_defined_tags")
        changes = self._changes_from_payload(payload.get("changes"), original_statements, proposed_statements, False)
        unparseable = self._changes_from_payload(payload.get("unparseable"), original_statements, proposed_statements, True)
        principal_references = self._principal_references_from_payload(payload.get("principal_references", []))
        changed_indices = {index for index, values in enumerate(zip(original_statements, proposed_statements)) if values[0] != values[1]}
        if changed_indices != {change.index for change in changes}:
            raise ValueError("audit report statement changes do not match proposed statements")
        snapshot = PolicySnapshot(payload["id"], payload["name"], payload["compartment_id"], payload["lifecycle_state"], original_statements, original_tags, payload["etag_before"], payload["version_date"], defined_tags)
        status = payload.get("status")
        if status not in {"previewed", "unchanged"}:
            raise ValueError("audit report policy status must be previewed or unchanged")
        return PolicyProposal(snapshot, proposed_statements, proposed_tags, changes, unparseable, principal_references, status=status)

    def _changes_from_payload(self, payload: object, original: list[str], proposed: list[str], require_error: bool) -> list[StatementChange]:
        """Validate serialized statement changes against their statement arrays."""
        if not isinstance(payload, list):
            raise ValueError("audit report statement changes must be a list")
        changes = []
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("index"), int):
                raise ValueError("audit report statement change is invalid")
            index = item["index"]
            error = item.get("error")
            if index < 0 or index >= len(original) or item.get("original") != original[index] or item.get("proposed") != proposed[index]:
                raise ValueError("audit report statement change does not match its statement array")
            if require_error != isinstance(error, str):
                raise ValueError("audit report parse-error state is invalid")
            changes.append(StatementChange(index, original[index], proposed[index], error))
        return changes

    def _principal_reference_payload(self, reference: PrincipalReference) -> dict:
        """Serialize one target Identity Domain principal reference."""
        return {"principal_type": reference.principal_type, "name": reference.name, "statement_index": reference.statement_index}

    def _principal_references_from_payload(self, payload: object) -> list[PrincipalReference]:
        """Validate and reconstruct stored named principal references."""
        if not isinstance(payload, list):
            raise ValueError("audit report principal_references must be a list")
        references = []
        for item in payload:
            if not isinstance(item, dict) or item.get("principal_type") not in {"group", "dynamic-group"} or not isinstance(item.get("name"), str) or not item["name"] or not isinstance(item.get("statement_index"), int):
                raise ValueError("audit report principal reference is invalid")
            references.append(PrincipalReference(item["principal_type"], item["name"], item["statement_index"]))
        return references

    def _string_list(self, value: object, name: str) -> list[str]:
        """Validate and copy a JSON string list."""
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"audit report {name} must be a string list")
        return list(value)

    def _string_map(self, value: object, name: str) -> dict[str, str]:
        """Validate and copy a JSON string map."""
        if not isinstance(value, dict) or any(not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()):
            raise ValueError(f"audit report {name} must be a string map")
        return dict(value)

    def _nested_string_map(self, value: object, name: str) -> dict[str, dict[str, str]]:
        """Validate and copy a JSON namespace-to-string-map value."""
        if not isinstance(value, dict) or any(not isinstance(namespace, str) or not isinstance(tags, dict) for namespace, tags in value.items()):
            raise ValueError(f"audit report {name} must be a namespace-to-string-map")
        if any(not isinstance(key, str) or not isinstance(item, str) for tags in value.values() for key, item in tags.items()):
            raise ValueError(f"audit report {name} must contain string keys and values")
        return {namespace: dict(tags) for namespace, tags in value.items()}

    def _change_payload(self, change: StatementChange) -> dict:
        """Serialize one statement diff or parse failure."""
        return {"index": change.index, "original": change.original, "proposed": change.proposed, "error": change.error}

    def _summary(self, proposals: list[PolicyProposal], principal_validation: dict | None = None) -> dict:
        """Summarize discovered and changing policy counts."""
        return {
            "discovered_policies": len(proposals),
            "changing_policies": sum(1 for proposal in proposals if proposal.changed),
            "changed_statements": sum(len(proposal.changes) for proposal in proposals),
            "unparseable_statements": sum(len(proposal.unparseable) for proposal in proposals),
            "updated_policies": sum(1 for proposal in proposals if proposal.status == "updated"),
            "failed_policies": sum(1 for proposal in proposals if proposal.status in {"failed", "preflight_failed"}),
            "untouched_policies": sum(1 for proposal in proposals if proposal.status == "untouched"),
            "unchanged_policies": sum(1 for proposal in proposals if proposal.status == "unchanged"),
            "missing_principal_names": self.missing_principal_names(principal_validation),
        }

    @staticmethod
    def missing_principal_names(principal_validation: dict | None) -> list[str]:
        """Return sorted principal type/name summaries for successful validation results."""
        if not isinstance(principal_validation, dict) or principal_validation.get("status") != "completed":
            return []
        return sorted(f"{principal['principal_type']}: {principal['name']}" for principal in principal_validation.get("missing_principals", []))
