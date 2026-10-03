"""Privacy-preserving provenance verification for ModelLedger events.

The chain is an append-only claim store.  This module evaluates those claims
without requiring private prompts or generation metadata to be disclosed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol


ZERO32 = b"\x00" * 32


class IssuerRegistry(Protocol):
    def role_at(self, who: str, timestamp: int) -> str:
        ...


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Serialize a record deterministically before hashing it."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def record_digest(record: Mapping[str, Any]) -> bytes:
    """Return the SHA-256 digest of an off-chain record.

    ``record_hash`` is excluded so a record can carry its own digest.
    """
    payload = {key: value for key, value in record.items() if key != "record_hash"}
    return sha256(canonical_json(payload))


def commitment(secret: bytes, value: str) -> bytes:
    """Commit to private data without putting the data on-chain."""
    return sha256(secret + value.encode("utf-8"))


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    event_ids: tuple[int, ...] = ()


@dataclass
class VerificationResult:
    status: str
    trusted: bool
    artifact_hash_valid: bool | None
    findings: list[Finding] = field(default_factory=list)
    verified_event_ids: tuple[int, ...] = ()

    @property
    def valid(self) -> bool:
        return self.status == "verified"


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        value = value.removeprefix("0x")
        return bytes.fromhex(value)
    raise TypeError("hash values must be bytes or hexadecimal strings")


def _event_id(event: Mapping[str, Any]) -> int:
    return int(event["id"])


def verify_artifact(
    artifact_hash: bytes,
    events: Iterable[Mapping[str, Any]],
    registry: IssuerRegistry,
    *,
    content: bytes | None = None,
    private_values: Mapping[int, tuple[bytes, str]] | None = None,
) -> VerificationResult:
    """Verify an artifact and its complete, trusted provenance history.

    ``events`` may come from multiple ledgers/systems; event IDs only need to
    be unique within this input.  ``private_values`` is optional and is used
    solely to verify commitments.  Its values are never copied into findings.
    """
    target = _as_bytes(artifact_hash)
    all_events = list(events)
    findings: list[Finding] = []
    artifact_hash_valid: bool | None = None

    if content is not None:
        artifact_hash_valid = hmac.compare_digest(sha256(content), target)
        if not artifact_hash_valid:
            findings.append(Finding("artifact-tampered", "content does not match the claimed artifact hash"))

    by_artifact: dict[bytes, list[Mapping[str, Any]]] = {}
    by_id: dict[int, Mapping[str, Any]] = {}
    for event in all_events:
        event_id = _event_id(event)
        if event_id in by_id:
            findings.append(Finding("duplicate-event-id", "multiple records use the same event id", (event_id,)))
        by_id[event_id] = event
        try:
            by_artifact.setdefault(_as_bytes(event["artifact_hash"]), []).append(event)
        except (KeyError, TypeError, ValueError):
            findings.append(Finding("malformed-event", "event has an invalid artifact hash", (event_id,)))

    claims = by_artifact.get(target, [])
    if not claims:
        findings.append(Finding("incomplete-history", "no event claims the requested artifact"))
    if len(claims) > 1:
        findings.append(Finding("conflicting-claims", "multiple events claim the same artifact", tuple(_event_id(e) for e in claims)))

    visited: set[int] = set()
    visiting: set[int] = set()

    def walk(event: Mapping[str, Any]) -> None:
        event_id = _event_id(event)
        if event_id in visited:
            return
        if event_id in visiting:
            findings.append(Finding("cyclic-history", "provenance parent links contain a cycle", (event_id,)))
            return
        visiting.add(event_id)
        try:
            artifact = _as_bytes(event["artifact_hash"])
            parent = _as_bytes(event["parent_hash"])
            event_type = event["event_type"]
            signer = event["signer"]
            timestamp = int(event["timestamp"])
            role = registry.role_at(signer, timestamp)
            if role == "None":
                findings.append(Finding("untrusted-issuer", "event signer was not trusted at event time", (event_id,)))
            elif event_type == "Generate" and role != "Generator":
                findings.append(Finding("role-mismatch", "generator event was signed by a non-generator issuer", (event_id,)))
            elif event_type == "Transform" and role not in {"Editor", "Generator"}:
                findings.append(Finding("role-mismatch", "transform event was signed by an issuer without edit authority", (event_id,)))
            elif event_type == "Publish" and role != "Publisher":
                findings.append(Finding("role-mismatch", "publish event was signed by a non-publisher issuer", (event_id,)))

            if event_type == "Generate":
                if parent != ZERO32:
                    findings.append(Finding("invalid-parent", "generate events must not have a parent", (event_id,)))
            elif event_type in {"Transform", "Publish"}:
                if parent == ZERO32:
                    findings.append(Finding("incomplete-history", "transform/publish event has no parent", (event_id,)))
                else:
                    parent_events = by_artifact.get(parent, [])
                    if not parent_events:
                        findings.append(Finding("incomplete-history", "parent artifact is not present in supplied history", (event_id,)))
                    for parent_event in parent_events:
                        walk(parent_event)

            if "record" in event:
                expected = record_digest(event["record"])
                claimed = _as_bytes(event.get("record_hash", ZERO32))
                if not hmac.compare_digest(expected, claimed):
                    findings.append(Finding("record-tampered", "off-chain record does not match its on-chain digest", (event_id,)))

            if private_values and event_id in private_values:
                secret, value = private_values[event_id]
                expected = commitment(secret, value)
                actual = _as_bytes(event.get("commitment_root", ZERO32))
                if not hmac.compare_digest(expected, actual):
                    findings.append(Finding("commitment-mismatch", "private commitment does not match the event", (event_id,)))
        except (KeyError, TypeError, ValueError):
            findings.append(Finding("malformed-event", "event is missing or contains invalid fields", (event_id,)))
        finally:
            visiting.discard(event_id)
            visited.add(event_id)

    for claim in claims:
        walk(claim)

    unique_findings = list(dict.fromkeys(findings))
    trusted = not any(f.code in {"untrusted-issuer", "role-mismatch"} for f in unique_findings)
    if unique_findings:
        status = "untrusted" if not trusted else "invalid"
    else:
        status = "verified"
    return VerificationResult(
        status=status,
        trusted=trusted,
        artifact_hash_valid=artifact_hash_valid,
        findings=unique_findings,
        verified_event_ids=tuple(sorted(visited)),
    )
