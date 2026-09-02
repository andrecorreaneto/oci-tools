"""Preview and apply CLI for bulk Identity Domain qualification of OCI policies."""

from __future__ import annotations

import argparse
import configparser
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Callable, TextIO

from oci_cli import OciCliError, OciCliGateway
from workflow import AuditReportStore, PolicyDomainUpdateApplication, PolicyReportApplyApplication


class OciConfigError(ValueError):
    """Raised when the selected OCI CLI profile lacks required context."""


class OciConfigReader:
    """Read non-secret tenancy context from an OCI CLI configuration profile."""

    def __init__(self, path: Path, profile: str):
        """Create a reader for one configuration file and profile."""
        self.path = path
        self.profile = profile

    def tenancy_id(self) -> str:
        """Return the tenancy OCID without reading private-key content."""
        parser = configparser.RawConfigParser()
        if not parser.read(self.path, encoding="utf-8"):
            raise OciConfigError(f"OCI config file not found: {self.path}")
        if not parser.has_section(self.profile) and self.profile != parser.default_section:
            raise OciConfigError(f"OCI profile {self.profile!r} not found in {self.path}")
        section = parser[self.profile]
        tenancy_id = section.get("tenancy", "").strip()
        if not tenancy_id:
            raise OciConfigError(f"OCI profile {self.profile!r} has no tenancy")
        return tenancy_id


def validate_inputs(tag_namespace: str | None, tag_key: str, tag_value: str, identity_domain_name: str) -> None:
    """Validate exact freeform tag selector and canonical quoted-domain inputs."""
    if tag_namespace is not None and not _is_valid_tag_component(tag_namespace):
        raise ValueError("tag_namespace must be 1-100 printable ASCII characters without spaces, periods, or single quotes")
    if not _is_valid_tag_component(tag_key):
        raise ValueError("tag_key must be 1-100 printable ASCII characters without spaces, periods, or single quotes")
    logical_tag_value = normalize_tag_value(tag_value)
    if not logical_tag_value or len(tag_value) > 256 or "'" in tag_value or any(ord(character) < 32 or ord(character) == 127 for character in logical_tag_value):
        raise ValueError("tag_value must be 1-256 characters, contain no single quote or control character, and may end with one legacy LF or CRLF")
    if not identity_domain_name or any(character in identity_domain_name for character in ("/", "'")) or any(ord(character) < 32 for character in identity_domain_name):
        raise ValueError("identity_domain_name must be non-empty and contain no slash, single quote, or control character")


def _is_valid_tag_component(value: str) -> bool:
    """Return whether one tag namespace or key is safe for exact Search syntax."""
    return 1 <= len(value) <= 100 and not any(ord(character) < 33 or ord(character) > 126 or character in ".'" for character in value)


def normalize_tag_value(tag_value: str) -> str:
    """Remove one optional legacy LF or CRLF suffix from a logical tag value."""
    if tag_value.endswith("\r\n"):
        return tag_value[:-2]
    return tag_value[:-1] if tag_value.endswith("\n") else tag_value


def build_parser() -> argparse.ArgumentParser:
    """Build preview/apply mode inputs and optional OCI context flags."""
    parser = argparse.ArgumentParser(description="Bulk-qualify Core LZ IAM policy subjects with an Identity Domain.")
    parser.add_argument("--tag-namespace")
    parser.add_argument("--tag-key")
    parser.add_argument("--tag-value")
    parser.add_argument("--identity-domain-name")
    parser.add_argument("--identity-domain-profile")
    parser.add_argument("--audit-report")
    parser.add_argument("--confirm-identity-domain-name")
    parser.add_argument("--oci-cli", default="oci")
    parser.add_argument("--profile", default="DEFAULT")
    parser.add_argument("--config-file", default=str(Path.home() / ".oci" / "config"))
    parser.add_argument("--region")
    parser.add_argument("--report-dir", default=".")
    return parser


def main(argv: list[str] | None = None, gateway_factory: Callable[..., OciCliGateway] = OciCliGateway, stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr, now: Callable[[], datetime] | None = None) -> int:
    """Validate context and run preview or audit-driven apply mode."""
    arguments = build_parser().parse_args(argv)
    try:
        is_apply = arguments.audit_report is not None
        if is_apply:
            if any(value is not None for value in (arguments.tag_namespace, arguments.tag_key, arguments.tag_value, arguments.identity_domain_name, arguments.identity_domain_profile)):
                raise ValueError("audit-report apply mode does not accept tag-namespace, tag-key, tag-value, identity-domain-name, or identity-domain-profile")
            if not arguments.confirm_identity_domain_name:
                raise ValueError("audit-report apply mode requires confirm-identity-domain-name")
            audit_store = AuditReportStore(Path(arguments.audit_report).expanduser().resolve())
            report, proposals = audit_store.load_preview()
            identity_domain_name = report["inputs"]["identity_domain_name"]
            if arguments.confirm_identity_domain_name != identity_domain_name:
                raise ValueError("confirm_identity_domain_name must exactly match the audit report Identity Domain")
        else:
            if any(value is None for value in (arguments.tag_key, arguments.tag_value, arguments.identity_domain_name)):
                raise ValueError("preview mode requires tag-key, tag-value, and identity-domain-name")
            if arguments.confirm_identity_domain_name is not None:
                raise ValueError("confirm-identity-domain-name is valid only with audit-report")
            validate_inputs(arguments.tag_namespace, arguments.tag_key, arguments.tag_value, arguments.identity_domain_name)
            logical_tag_value = normalize_tag_value(arguments.tag_value)
            identity_domain_name = arguments.identity_domain_name
            report_dir = Path(arguments.report_dir).expanduser().resolve()
            report_dir.mkdir(parents=True, exist_ok=True)
            clock = now or (lambda: datetime.now(timezone.utc))
        config_path = Path(arguments.config_file).expanduser().resolve()
        tenancy_id = OciConfigReader(config_path, arguments.profile).tenancy_id()
        gateway = gateway_factory(arguments.oci_cli, arguments.profile, str(config_path), arguments.region)
        print(f"Validating Identity Domain {identity_domain_name!r} ...", file=stdout, flush=True)
        try:
            identity_domain_endpoint = gateway.get_identity_domain_endpoint(tenancy_id, identity_domain_name)
        except OciCliError as error:
            if is_apply:
                raise
            report_time = clock().astimezone(timezone.utc)
            report_path = report_dir / f"iam-policies-bulk-update-{report_time.strftime('%Y%m%dT%H%M%SZ')}.json"
            audit_store = AuditReportStore(report_path)
            report = audit_store.create_identity_domain_validation_failure({"tag_namespace": arguments.tag_namespace, "tag_key": arguments.tag_key, "tag_value": logical_tag_value, "resolved_tag_values": [], "identity_domain_name": identity_domain_name, "identity_domain_profile": arguments.identity_domain_profile, "run_timestamp": report_time.isoformat(timespec="milliseconds").replace("+00:00", "Z")}, str(error), report_time)
            audit_store.write(report)
            print(f"ERROR: Invalid identity domain {identity_domain_name!r} provided in --identity-domain-name. Details written to audit report: {report_path}", file=stderr, flush=True)
            return 2
        print("Identity Domain validated.", file=stdout, flush=True)
        if is_apply:
            return PolicyReportApplyApplication(gateway, stdout).run(audit_store, report, proposals, arguments.confirm_identity_domain_name)
        return PolicyDomainUpdateApplication(gateway, report_dir, stdout, clock, identity_domain_endpoint, arguments.identity_domain_profile).run(arguments.tag_namespace, arguments.tag_key, logical_tag_value, identity_domain_name)
    except (OciCliError, OciConfigError, ValueError) as error:
        print(f"ERROR: {error}", file=stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
