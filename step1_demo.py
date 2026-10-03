"""step1_demo.py - proves the on-chain foundation of ModelLedger works.

Scenario
  1. Admin registers a trusted Generator (ImageGen-A) and a trusted Editor (Upscaler-B).
  2. ImageGen-A records the creation of an image.            (hop 1: Generate)
  3. Upscaler-B records an upscaled version of that image.   (hop 2: Transform)
  4. A rogue, unregistered account records its own claims, including a
     conflicting claim over the upscaled image.              (self-asserted / conflict)
  5. Admin revokes Upscaler-B; old records stay valid, new ones would not be.

Run:  python step1_demo.py
"""
import hashlib

from chain import Ledger, ZERO32, connect


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def short(h: bytes) -> str:
    return h.hex()[:10] + "..."


def show(ledger: Ledger, ev: dict) -> None:
    role_then = ledger.role_at(ev["signer"], ev["timestamp"])
    print(
        f"  event #{ev['id']}: {ev['event_type']:<9} artifact={short(ev['artifact_hash'])} "
        f"parent={short(ev['parent_hash']) if ev['parent_hash'] != ZERO32 else '(none)':<13} "
        f"signer={ledger.issuer_name(ev['signer']):<14} role-at-the-time={role_then}"
    )


def main() -> None:
    w3 = connect()  # in-memory chain; connect("http://127.0.0.1:8545") for a real node
    admin, gen_a, editor_b, rogue = w3.eth.accounts[:4]

    print("Compiling + deploying ModelLedger ...")
    ledger = Ledger.deploy(w3, deployer=admin)
    print(f"Deployed at {ledger.contract.address}\n")

    # 1. Trusted issuer registry
    ledger.register_issuer(admin, gen_a, "Generator", "ImageGen-A")
    ledger.register_issuer(admin, editor_b, "Editor", "Upscaler-B")
    print("Registered ImageGen-A (Generator) and Upscaler-B (Editor)\n")

    # Pretend these byte strings are image files.
    original = sha(b"image bytes produced by ImageGen-A")
    upscaled = sha(b"image bytes after Upscaler-B")
    forged = sha(b"image bytes a rogue claims to have generated")

    prompt_commitment = sha(b"secret-salt" + b"a cat astronaut, oil painting")  # private prompt stays off-chain

    # 2 + 3. A legitimate two-hop chain
    ledger.record_event(gen_a, original, ZERO32, sha(b"record-1"), prompt_commitment, 0xAAAA, "Generate")
    ledger.record_event(editor_b, upscaled, original, sha(b"record-2"), ZERO32, 0xAAAB, "Transform")

    # 4. Rogue account: a fake "generation", plus a conflicting claim over the upscaled image
    ledger.record_event(rogue, forged, ZERO32, sha(b"record-3"), ZERO32, 0xBBBB, "Generate")
    ledger.record_event(rogue, upscaled, ZERO32, sha(b"record-4"), ZERO32, 0xAAAB, "Generate")

    print("Everything on the ledger:")
    for i in range(ledger.event_count()):
        show(ledger, ledger.get_event(i))

    print("\nConflict check - who claims the upscaled image?")
    claims = ledger.events_for_artifact(upscaled)
    for ev in claims:
        show(ledger, ev)
    if len(claims) > 1:
        print("  -> CONFLICT: multiple claims for one artifact. The verifier must flag this.")

    # 5. Revocation
    ledger.revoke_issuer(admin, editor_b)
    now = w3.eth.get_block("latest")["timestamp"]
    old_event = ledger.get_event(1)
    print("\nAfter revoking Upscaler-B:")
    print(f"  role at time of its old event : {ledger.role_at(editor_b, old_event['timestamp'])}")
    print(f"  role right now                : {ledger.role_at(editor_b, now)}")


if __name__ == "__main__":
    main()
