"""OCI policy discovery and Core LZ tag selection."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from models import PolicySnapshot


class PolicyDiscovery:
    """Discover policies whose current tags match one exact selector."""

    def __init__(self, oci: Any, progress: Callable[[str], None] | None = None):
        """Create discovery around an OCI CLI gateway."""
        self.oci = oci
        self.progress = progress or (lambda message: None)
        self.resolved_tag_values: list[str] = []

    def discover(self, tag_namespace: str | None, tag_key: str, tag_value: str) -> list[PolicySnapshot]:
        """Paginate, deduplicate, GET, and exact-filter current policies."""
        logical_tag_value = self._logical_tag_value(tag_value)
        candidate_tag_values = [logical_tag_value, f"{logical_tag_value}\n", f"{logical_tag_value}\r\n"]
        self.progress(f"Searching exact tag encodings for {logical_tag_value!r} ...")
        with ThreadPoolExecutor(max_workers=len(candidate_tag_values)) as executor:
            futures = {tag_value: executor.submit(self._search_all_pages, tag_namespace, tag_key, tag_value) for tag_value in candidate_tag_values}
            search_results = {tag_value: futures[tag_value].result() for tag_value in candidate_tag_values}
        for tag_value in candidate_tag_values:
            self.progress(f"Exact tag encoding {tag_value!r} returned {len(search_results[tag_value])} policy identifiers.")
        identifiers = set().union(*search_results.values())
        ordered_identifiers = sorted(identifiers)
        self.progress(f"Fetching current details for {len(ordered_identifiers)} policies ...")
        policies = []
        for index, policy_id in enumerate(ordered_identifiers, 1):
            position = f"[{index}/{len(ordered_identifiers)}]"
            self.progress(f"{position} Fetching policy details ...")
            policy = self.oci.get_policy(policy_id)
            policies.append(policy)
            self.progress(f"{position} Fetched policy {policy.name}.")
        self.progress(f"Policy detail fetch complete: {len(policies)} policies fetched.")
        selected = [policy for policy in policies if self._matches(policy, tag_namespace, tag_key, candidate_tag_values)]
        self.resolved_tag_values = [tag_value for tag_value in candidate_tag_values if any(self._tag_value(policy, tag_namespace, tag_key) == tag_value for policy in selected)]
        self.progress(f"Resolved {len(self.resolved_tag_values)} exact tag encoding(s).")
        return sorted(selected, key=lambda policy: (policy.compartment_id, policy.name, policy.id))

    def _search_all_pages(self, tag_namespace: str | None, tag_key: str, tag_value: str) -> set[str]:
        """Return every exact Search identifier for one physical tag encoding."""
        identifiers: set[str] = set()
        page: str | None = None
        while True:
            page_identifiers, page = self.oci.search_policy_page(tag_namespace, tag_key, tag_value, page)
            identifiers.update(page_identifiers)
            if page is None:
                return identifiers

    def _logical_tag_value(self, tag_value: str) -> str:
        """Remove one optional legacy line ending from the supplied logical value."""
        if tag_value.endswith("\r\n"):
            return tag_value[:-2]
        return tag_value[:-1] if tag_value.endswith("\n") else tag_value

    def _matches(self, policy: PolicySnapshot, tag_namespace: str | None, tag_key: str, candidate_tag_values: list[str]) -> bool:
        """Match the current tag to one physical encoding queried by exact Search."""
        return self._tag_value(policy, tag_namespace, tag_key) in candidate_tag_values

    def _tag_value(self, policy: PolicySnapshot, tag_namespace: str | None, tag_key: str) -> str | None:
        """Return the selected freeform or defined tag value from one policy."""
        return policy.defined_tags.get(tag_namespace, {}).get(tag_key) if tag_namespace else policy.freeform_tags.get(tag_key)
