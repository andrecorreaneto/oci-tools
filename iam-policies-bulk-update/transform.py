"""IAM policy subject transformation for identity domains."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class StatementTransform:
    """Result of transforming one IAM policy statement."""

    statement: str
    changed: bool
    error: str | None = None
    principal_type: str | None = None
    named_principals: tuple[str, ...] = ()


class PolicyStatementTransformer:
    """Qualify named group and dynamic-group subjects with one identity domain."""

    PREFIX_PATTERN = re.compile(r"^(\s*allow\s+(dynamic-group|group)\s+)(.*)$", re.IGNORECASE)

    def __init__(self, identity_domain_name: str):
        """Create a transformer for the validated target identity domain."""
        self.identity_domain_name = identity_domain_name

    def transform(self, statement: str) -> StatementTransform:
        """Transform one supported named-principal subject."""
        match = self.PREFIX_PATTERN.match(statement)
        if match is None:
            return StatementTransform(statement, False)
        principal_type = match.group(2).lower()
        remainder = match.group(3)
        separator_index = self._to_separator_index(remainder)
        if separator_index < 0:
            return StatementTransform(statement, False, "missing `to` separator outside quoted subject")
        try:
            principals = self._split_principals(remainder[:separator_index].strip())
            qualified_principals = [self._qualify_principal(principal) for principal in principals]
        except ValueError as error:
            return StatementTransform(statement, False, str(error))
        proposed = f"{match.group(1)}{', '.join(principal[0] for principal in qualified_principals)}{remainder[separator_index:]}"
        named_principals = tuple(principal[1] for principal in qualified_principals if principal[1] is not None)
        return StatementTransform(proposed, proposed != statement, None, principal_type, named_principals)

    def _to_separator_index(self, remainder: str) -> int:
        """Locate the `to` separator outside single-quoted principal names."""
        quoted = False
        for index, character in enumerate(remainder):
            if character == "'":
                quoted = not quoted
            elif not quoted and re.match(r"\s+to\s+", remainder[index:], re.IGNORECASE):
                return index
        return -1

    def _split_principals(self, subject: str) -> list[str]:
        """Split a principal list on commas outside quoted names."""
        principals: list[str] = []
        start = 0
        quoted = False
        for index, character in enumerate(subject):
            if character == "'":
                quoted = not quoted
            elif character == "," and not quoted:
                principals.append(subject[start:index].strip())
                start = index + 1
        if quoted:
            raise ValueError("unbalanced single quote in subject")
        principals.append(subject[start:].strip())
        if any(not principal for principal in principals):
            raise ValueError("empty principal in subject")
        return principals

    def _qualify_principal(self, principal: str) -> tuple[str, str | None]:
        """Force a named principal to the target domain or preserve an OCID principal."""
        if re.fullmatch(r"id\s+ocid1\.[^\s,]+", principal, re.IGNORECASE):
            return principal, None
        slash_index = self._outside_quote_slash(principal)
        group_token = principal[slash_index + 1:] if slash_index >= 0 else principal
        group_name = self._parse_name(group_token.strip())
        return f"'{self.identity_domain_name}'/'{group_name}'", group_name

    def _outside_quote_slash(self, principal: str) -> int:
        """Locate a domain separator outside quoted domain/group names."""
        quoted = False
        slash_index = -1
        for index, character in enumerate(principal):
            if character == "'":
                quoted = not quoted
            elif character == "/" and not quoted:
                if slash_index >= 0:
                    raise ValueError(f"multiple domain separators in principal {principal!r}")
                slash_index = index
        if quoted:
            raise ValueError(f"unbalanced single quote in principal {principal!r}")
        return slash_index

    def _parse_name(self, value: str) -> str:
        """Return a quoted or unquoted group name without its delimiters."""
        if value.startswith("'"):
            if not value.endswith("'") or len(value) < 3 or "'" in value[1:-1]:
                raise ValueError(f"invalid quoted group name {value!r}")
            return value[1:-1]
        if not value or "'" in value or "/" in value:
            raise ValueError(f"invalid group name {value!r}")
        return value
