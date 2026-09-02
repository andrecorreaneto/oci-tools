"""OCI CLI gateway for IAM policy bulk updates."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Callable

from models import PolicySnapshot


class OciCliError(RuntimeError):
    """Raised when an OCI CLI command or response is invalid."""


class OciCliGateway:
    """Execute OCI Search and IAM operations without invoking a shell."""

    MAX_ERROR_OUTPUT = 4096

    def __init__(self, executable: str, profile: str | None, config_file: str | None, region: str | None, executor: Callable[[list[str]], dict[str, Any]] | None = None):
        """Create a gateway with reusable OCI CLI context flags."""
        self.executable = executable
        self.profile = profile
        self.config_file = config_file
        self.region = region
        self.executor = executor or self._execute

    def search_policy_page(self, tag_namespace: str | None, tag_key: str, tag_value: str, page: str | None) -> tuple[list[str], str | None]:
        """Search one page of policies carrying the exact selected tag triple."""
        query = f"query policy resources where (definedTags.namespace == '{tag_namespace}' && definedTags.key == '{tag_key}' && definedTags.value == '{tag_value}')" if tag_namespace else f"query policy resources where (freeformTags.key == '{tag_key}' && freeformTags.value == '{tag_value}')"
        arguments = [self.executable, "search", "resource", "structured-search", "--query-text", query, "--limit", "1000"]
        if page:
            arguments.extend(["--page", page])
        payload = self.executor(self._with_context(arguments))
        identifiers = [item["identifier"] for item in payload.get("data", {}).get("items", [])]
        return identifiers, payload.get("opc-next-page")

    def get_policy(self, policy_id: str) -> PolicySnapshot:
        """Return the current policy body and ETag."""
        payload = self.executor(self._with_context([self.executable, "iam", "policy", "get", "--policy-id", policy_id]))
        data = payload.get("data") or {}
        try:
            return PolicySnapshot(data["id"], data["name"], data["compartment-id"], data["lifecycle-state"], list(data["statements"]), dict(data.get("freeform-tags") or {}), payload.get("etag"), data.get("version-date"), {namespace: dict(tags) for namespace, tags in (data.get("defined-tags") or {}).items()})
        except (KeyError, TypeError) as error:
            raise OciCliError(f"incomplete policy response for {policy_id}") from error

    def identity_domain_exists(self, tenancy_id: str, identity_domain_name: str) -> bool:
        """Verify the exact Identity Domain resource name through OCI CLI."""
        arguments = [self.executable, "iam", "domain", "list", "--compartment-id", tenancy_id, "--name", identity_domain_name, "--all"]
        payload = self.executor(self._with_context(arguments))
        return len(payload.get("data", [])) == 1

    def get_identity_domain_endpoint(self, tenancy_id: str, identity_domain_name: str) -> str:
        """Return the target Identity Domain base URL for the Identity Domains CLI."""
        arguments = [self.executable, "iam", "domain", "list", "--compartment-id", tenancy_id, "--name", identity_domain_name, "--all"]
        payload = self.executor(self._with_context(arguments))
        domains = payload.get("data", [])
        if len(domains) != 1 or not isinstance(domains[0], dict):
            raise OciCliError(f"identity_domain_name {identity_domain_name!r} does not identify exactly one OCI Identity Domain")
        domain_url = domains[0].get("url") or domains[0].get("home-region-url")
        if not isinstance(domain_url, str) or not domain_url:
            raise OciCliError(f"identity_domain_name {identity_domain_name!r} has no Identity Domains URL")
        normalized_url = domain_url.rstrip("/")
        return normalized_url[:-len("/admin/v1")] if normalized_url.endswith("/admin/v1") else normalized_url

    def list_identity_domain_principals(self, endpoint: str, identity_domain_profile: str | None) -> dict[str, set[str]]:
        """List named groups and dynamic resource groups in one Identity Domain."""
        groups_payload = self.executor(self._with_context([self.executable, "identity-domains", "groups", "list", "--all", "--endpoint", endpoint], identity_domain_profile))
        dynamic_groups_payload = self.executor(self._with_context([self.executable, "identity-domains", "dynamic-resource-groups", "list", "--all", "--endpoint", endpoint], identity_domain_profile))
        return {"group": self._display_names(groups_payload), "dynamic-group": self._display_names(dynamic_groups_payload)}

    def update_policy(self, policy_id: str, statements_path: Path, tags_path: Path, etag: str, version_date: str | None) -> dict[str, Any]:
        """Update statements, version date, and freeform tags under optimistic concurrency."""
        version_date_arguments = ["--version-date", version_date] if version_date is not None else ["--version-date="]
        arguments = [self.executable, "iam", "policy", "update", "--policy-id", policy_id, "--statements", f"file://{statements_path}", *version_date_arguments, "--freeform-tags", f"file://{tags_path}", "--if-match", etag, "--force"]
        return self.executor(self._with_context(arguments))

    def _with_context(self, arguments: list[str], profile_override: str | None = None) -> list[str]:
        """Append selected OCI CLI global context flags to one command."""
        result = list(arguments)
        selected_profile = profile_override or self.profile
        if selected_profile:
            result.extend(["--profile", selected_profile])
        if self.config_file:
            result.extend(["--config-file", self.config_file])
        if self.region:
            result.extend(["--region", self.region])
        result.extend(["--output", "json"])
        return result

    def _execute(self, arguments: list[str]) -> dict[str, Any]:
        """Run OCI CLI and parse its JSON output."""
        completed = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", check=False)
        if completed.returncode != 0:
            message = self._command_output(completed)
            raise OciCliError(f"OCI CLI command failed ({' '.join(arguments[1:4])}): {message}")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise OciCliError(f"OCI CLI returned invalid JSON: {self._command_output(completed)}") from error

    def _command_output(self, completed: subprocess.CompletedProcess) -> str:
        """Return bounded stderr and stdout excerpts that preserve CLI failure causes."""
        excerpts = []
        if completed.stderr.strip():
            excerpts.append(f"stderr: {completed.stderr.strip()[:self.MAX_ERROR_OUTPUT]}")
        if completed.stdout.strip():
            excerpts.append(f"stdout: {completed.stdout.strip()[:self.MAX_ERROR_OUTPUT]}")
        return "\n".join(excerpts) or "OCI CLI exited without output"

    def _display_names(self, payload: dict[str, Any]) -> set[str]:
        """Extract SCIM display names from one Identity Domains list response."""
        data = payload.get("data") or {}
        resources = (data.get("resources") or data.get("Resources") or []) if isinstance(data, dict) else []
        return {name for resource in resources if isinstance(resource, dict) and isinstance((name := resource.get("display-name") or resource.get("displayName")), str)}
