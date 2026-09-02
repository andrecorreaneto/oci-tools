# IAM Policies Bulk Update

This tool updates live OCI IAM policies. It searches for policies tagged with a specific tag namespace (for defined-tags), key and value, given as input parameters. It then qualifies (or re-qualifies) named *group* and *dynamic-group* policy subjects with one OCI Identity Domain, also given as an input parameter.

This is an out-of-band operation. It does not update Terraform configuration or state. If the policies are managed by Terraform, a later Terraform apply can revert the live policy statements.

## Behavior

The tool:

1. Validates the requested Identity Domain through OCI CLI.
2. Searches for OCI IAM policies carrying the requested exact freeform tag key and value.
3. Fetches every Search result and keeps only policies whose current tag pair still matches exactly.
4. Gets every selected policy and transforms supported statement subjects.
5. Writes complete discovered-policy and proposed-change details to the audit report and prints only summary counts to the console.
6. Writes a timestamped audit/recovery JSON file.
7. Exits in preview-only mode without mutating OCI.
8. Loads the reviewed audit report in a separate apply command without repeating discovery.
9. Requires an exact case-sensitive Identity Domain confirmation argument.
10. Re-fetches all changing policies and verifies their statements, tags, lifecycle, version dates, and ETags before the first write.
11. Updates and verifies policies sequentially, stopping on the first failure without rollback.
12. During preview, checks named `group` and `dynamic-group` subjects against the target Identity Domain and records missing principals without blocking the run.

## Subject transformation

Named groups are qualified using OCI's canonical quoted syntax:

```text
allow group NetworkAdmins to manage vcns in tenancy
→ allow group 'Domain-B'/'NetworkAdmins' to manage vcns in tenancy
```

Dynamic groups and comma-separated subjects are also supported:

```text
allow dynamic-group workers,'OldDomain'/'jobs' to use instances in tenancy
→ allow dynamic-group 'Domain-B'/'workers', 'Domain-B'/'jobs' to use instances in tenancy
```

Existing domain qualifiers are replaced with the requested domain. `group id <OCID>` and `dynamic-group id <OCID>` subjects remain unchanged.

Other principal types are unchanged. An unparseable `group` or `dynamic-group` statement is preserved and reported while other safely parsed statements in that policy may still update.

## Policy selection

OCI Search runs this structured query:

```text
query policy resources where
  (freeformTags.key == '<tag-key>' && freeformTags.value == '<tag-value>')
```

`==` makes both selector comparisons case-sensitive. The supplied `--tag-value` is a logical value. The tool searches its clean, LF, and CRLF exact encodings concurrently, deduplicates the policy IDs, and then fetches each candidate directly. A policy is retained only when its current tag matches one of the exact encodings that Search returned. This supports legacy line-ending differences without partial matching or a broad key-only search.

When `--tag-namespace` is omitted, the selector is a freeform tag. When it is supplied, the selector is an OCI defined tag and Search uses:

```text
query policy resources where
  (definedTags.namespace == '<tag-namespace>'
   && definedTags.key == '<tag-key>'
   && definedTags.value == '<tag-value>')
```

The same clean/LF/CRLF exact-resolution process applies to defined-tag values.

## Prerequisites

- Python 3.10 or newer.
- OCI CLI installed.
- OCI config file with a **required** user profile allowed to read & update the target IAM policies and list identity domains. Referred by the *--profile* input parameter.
- OCI config file with an **optional** user profile allowed to list groups and dynamic groups in the target identity domain. Use this for validating whether the groups and dynamic groups are valid in the new identity domain. The user must carry, at least, the User Administrator role in the new identity domain. Referred by the *--identity-domain-profile* input parameter. If not provided, principal validation in the target identity domain falls back to the *--profile* input parameter.

The tag key must contain 1–100 printable ASCII characters, excluding spaces, periods, and single quotes. The tag value must contain 1–256 characters and cannot contain a single quote or control character, except for optional trailing LF or CRLF legacy suffixes.

The Identity Domain name must be exact and cannot contain `/`, a single quote, or control characters.

## Usage

Run preview/discovery from the tool directory:

```bash
python policy_bulk_update.py \
  --tag-key oci-core-landing-zone \
  --tag-value ai/core/1.6.0 \
  --identity-domain-name vision-dev-identity-domain \
  --profile DEFAULT
  --identity-domain-profile VISION_DOMAIN_ADMIN
```

For a defined tag, add its namespace:

```bash
python policy_bulk_update.py \
  --tag-namespace Operations \
  --tag-key Workload \
  --tag-value ai/core/1.6.0 \
  --profile DEFAULT
  --identity-domain-name vision-dev-identity-domain
```

This writes a timestamped report with status `preview_only` and changes nothing in OCI. Apply that exact reviewed report without repeating discovery:

```bash
python policy_bulk_update.py \
  --audit-report iam-policies-bulk-update-20260828T185458Z.json \
  --confirm-identity-domain-name vision-dev-identity-domain \
  --profile DEFAULT
```

Preview mode requires `--tag-key`, `--tag-value`, and `--identity-domain-name`; `--tag-namespace` is optional and selects defined-tag mode. Apply mode requires `--audit-report` and `--confirm-identity-domain-name`. Defaults for the optional OCI context arguments are:

- `--oci-cli oci`
- `--profile DEFAULT`
- `--identity-domain-profile` falls back to `--profile`; when supplied, it is used only to list target-domain groups and dynamic resource groups.
- `--config-file ~/.oci/config`
- OCI CLI profile region when `--region` is omitted
- Current directory for `--report-dir`

## Progress output

The tool reports each major phase to standard output and flushes every message immediately so progress remains visible while OCI CLI calls are running. Preview includes messages similar to:

```text
Validating Identity Domain 'Domain-B' ...
Identity Domain validated.
Searching for policies tagged 'oci-core-landing-zone' = 'exacc/core/1.6.0' ...
Searching exact tag encodings for 'exacc/core/1.6.0' ...
Exact tag encoding 'exacc/core/1.6.0' returned 0 policy identifiers.
Exact tag encoding 'exacc/core/1.6.0\n' returned 0 policy identifiers.
Exact tag encoding 'exacc/core/1.6.0\r\n' returned 2 policy identifiers.
Fetching current details for 2 policies ...
[1/2] Fetching policy details ...
[1/2] Fetched policy policy-one.
[2/2] Fetching policy details ...
[2/2] Fetched policy policy-two.
Policy detail fetch complete: 2 policies fetched.
Resolved 1 exact tag encoding(s).
Discovery complete: 2 policies selected.
Audit report written: <path>
Preview summary: 2 policies selected, 2 changing, 4 statement changes, 0 unparseable.
Identity Domain principal validation: 1 missing principals across 1 policies.
Missing principals: dynamic-group: workers; group: Missing
Preview only. No OCI policies were changed.
Apply with: python policy_bulk_update.py --audit-report '<path>' --confirm-identity-domain-name 'Domain-B'
```

The separate apply command emits:

```text
Validating Identity Domain 'Domain-B' ...
Identity Domain validated.
Loaded preview-only audit report: <path>
Confirmation accepted. Running preflight for 2 policies ...
[1/2] Preflight checking policy policy-one ...
[1/2] Preflight passed for policy policy-one.
[2/2] Preflight checking policy policy-two ...
[2/2] Preflight passed for policy policy-two.
Preflight completed. No concurrent changes detected.
[1/2] Updating policy policy-one ...
[1/2] Verifying policy policy-one ...
[1/2] Policy policy-one verified.
Completed: 2 policies updated and verified.
```

The tool also prints an explicit final message when no policies are selected or no statements require changes. Errors remain on standard error. If the initial Identity Domain lookup fails, standard error names the supplied `--identity-domain-name` and points to a timestamped failure audit report; the report's `identity_domain_validation_error` field preserves the raw OCI CLI diagnostics.

## Preview and apply

The console displays selected-policy, changing-policy, changed-statement, and unparseable-statement counts. It does not display policy or statement diffs. Review the audit report for every discovered policy, proposed statement change, marker tag, and unparseable statement with its array index, original text, and reason.

Preview also validates named `group` and `dynamic-group` subjects against the target Identity Domain. Missing names are listed in the console as sorted `type: name` entries. The audit report stores the same list in `summary.missing_principal_names` and groups detailed findings by principal type/name with associated policy IDs, names, and statement indexes. OCID principals (`group id ...` and `dynamic-group id ...`) are preserved but not checked, because they are not domain-name references. If the caller cannot list Identity Domain groups, validation is recorded as unavailable and preview continues.

Policies with no changes are explicitly marked and are never updated merely to add the marker tag.

Preview writes:

```text
iam-policies-bulk-update-<YYYYMMDDTHHMMSSZ>.json
```

Review that report, then pass its path to `--audit-report` and retype the report's exact case-sensitive Identity Domain through `--confirm-identity-domain-name`. Apply accepts only a schema-version `1` report with status `preview_only` and a reviewed `version_date` field for every policy. It loads the stored original/proposed arrays, tags, version dates, ETags, and policy metadata, and performs no Resource Search or proposal regeneration. Development reports generated before `version_date` was added are rejected and require a new preview.

## Marker tag

Each policy with at least one rewritten statement receives or refreshes this freeform tag:

```text
iam-policies-bulk-update
  = <YYYY-MM-DDTHH:mm:ss.sssZ>
```

The same UTC millisecond timestamp is used for all policies in one run. Existing freeform tags are preserved.

Unchanged policies are not updated and do not receive the marker.

## Concurrency and failure handling

During audit-driven apply, all changing policies are fetched again before the first write. Any changed statement array, freeform tag map, defined-tag map, lifecycle state, version date, or ETag aborts the run with zero updates.

Apply freezes policy selection to the reviewed audit report and performs no Resource Search. A policy in the report that loses or changes the selection tag is rejected by preflight because its complete freeform-tag map changed. A policy created or newly tagged after preview is outside the reviewed set and is not considered by apply; run preview again to discover and review newly matching policies.

Updates use `oci iam policy update` with file-based statement/tag JSON, the reviewed `--version-date`, `--if-match`, and `--force`. OCI requires `--version-date` whenever statements are updated. On Windows, a null policy version date is encoded as the single argument `--version-date=` so the empty value survives native argument parsing. Temporary files are deleted after each attempt.

After each update, the policy is fetched again. Statement order/content, the complete freeform-tag map, defined-tag map, and version date must exactly equal the proposal.

The audit file is atomically refreshed after each attempted policy. On the first failure, previously verified updates remain in place and later policies are recorded as untouched.

There is no automatic rollback. Use the original statements and tags in the audit report for manual recovery.

## Audit report

The JSON report contains:

- Logical tag namespace/key/value selector, resolved exact tag encodings, Identity Domain name, optional Identity Domain profile, and UTC marker timestamp.
- Policy OCIDs, names, compartments, lifecycle states, version dates, freeform tags, defined tags, and ETags.
- Original and proposed statement arrays.
- Original and proposed freeform tags.
- Changed and unparseable statement details.
- Identity Domain principal-validation status and missing named principals with associated policies.
- Raw initial Identity Domain lookup diagnostics when `status` is `identity_domain_validation_failed`; such a report cannot be applied.
- `summary.missing_principal_names`, as sorted `type: name` entries.
- Per-policy status, error, and post-update ETag.
- Discovered, changed, updated, failed, untouched, and unchanged counts.

Treat the report as environment-specific IAM material. It can contain OCIDs, group names, policy conditions, descriptions, and compartment names.

## Exit codes

- `0`: preview report written, all updates verified, or no changes were needed.
- `1`: update or post-update verification failed, including partial completion.
- `2`: invalid input, no matching policies, discovery failure, or preflight failure before mutation.
