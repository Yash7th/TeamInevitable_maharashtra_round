import hashlib
import unittest

from provenance import ZERO32, commitment, record_digest, verify_artifact


class Registry:
    def __init__(self, roles):
        self.roles = roles

    def role_at(self, who, timestamp):
        return self.roles.get(who, "None")


def event(event_id, artifact, parent, event_type, signer, record=None, private=None):
    result = {
        "id": event_id,
        "artifact_hash": artifact,
        "parent_hash": parent,
        "record_hash": b"\x00" * 32,
        "commitment_root": b"\x00" * 32,
        "event_type": event_type,
        "signer": signer,
        "timestamp": event_id + 1,
    }
    if record is not None:
        result["record"] = record
        result["record_hash"] = record_digest(record)
    if private is not None:
        secret, value = private
        result["commitment_root"] = commitment(secret, value)
    return result


class ProvenanceVerificationTests(unittest.TestCase):
    def test_verifies_trusted_multi_system_transformation_and_private_commitment(self):
        original = hashlib.sha256(b"original").digest()
        output = hashlib.sha256(b"output").digest()
        secret = b"not disclosed"
        first = event(1, original, ZERO32, "Generate", "model-a", {"system": "model-a"})
        second = event(
            2, output, original, "Transform", "editor-b",
            {"system": "editor-b", "source": original.hex()}, (secret, "private prompt"),
        )
        result = verify_artifact(
            output, [first, second], Registry({"model-a": "Generator", "editor-b": "Editor"}),
            content=b"output", private_values={2: (secret, "private prompt")},
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.verified_event_ids, (1, 2))
        self.assertNotIn("private prompt", repr(result))

    def test_detects_fabricated_conflicting_claim(self):
        artifact = hashlib.sha256(b"same").digest()
        events = [
            event(1, artifact, ZERO32, "Generate", "model-a"),
            event(2, artifact, ZERO32, "Generate", "rogue"),
        ]
        result = verify_artifact(artifact, events, Registry({"model-a": "Generator"}))
        self.assertEqual(result.status, "untrusted")
        self.assertIn("conflicting-claims", {f.code for f in result.findings})

    def test_detects_tampering_and_incomplete_history(self):
        output = hashlib.sha256(b"output").digest()
        missing_parent = hashlib.sha256(b"missing").digest()
        result = verify_artifact(
            output,
            [event(7, output, missing_parent, "Transform", "editor-b")],
            Registry({"editor-b": "Editor"}),
            content=b"changed",
        )
        codes = {finding.code for finding in result.findings}
        self.assertEqual(result.status, "invalid")
        self.assertTrue({"artifact-tampered", "incomplete-history"} <= codes)

    def test_detects_record_and_commitment_tampering(self):
        artifact = hashlib.sha256(b"artifact").digest()
        record = {"system": "model-a", "version": "1"}
        item = event(3, artifact, ZERO32, "Generate", "model-a", record, (b"secret", "prompt"))
        item["record"]["version"] = "forged"
        item["commitment_root"] = b"\x01" * 32
        result = verify_artifact(
            artifact,
            [item],
            Registry({"model-a": "Generator"}),
            private_values={3: (b"secret", "prompt")},
        )
        codes = {finding.code for finding in result.findings}
        self.assertTrue({"record-tampered", "commitment-mismatch"} <= codes)


if __name__ == "__main__":
    unittest.main()
