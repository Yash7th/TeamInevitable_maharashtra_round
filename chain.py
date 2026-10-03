"""chain.py - thin Python wrapper around the ModelLedger smart contract.

Compiles the Solidity file, deploys it to a chain, and exposes friendly methods.
By default it uses an in-memory test chain (no Node.js, no wallet, nothing to run).
To use a real node later (Hardhat / Anvil / testnet), pass its URL to connect().
"""
from pathlib import Path

from web3 import Web3

SOLC_VERSION = "0.8.24"
CONTRACT_FILE = Path(__file__).parent / "ModelLedger.sol"

ZERO32 = b"\x00" * 32
ROLES = {"None": 0, "Generator": 1, "Editor": 2, "Publisher": 3}
ROLE_NAMES = {v: k for k, v in ROLES.items()}
EVENT_TYPES = {"Generate": 0, "Transform": 1, "Publish": 2}
EVENT_TYPE_NAMES = {v: k for k, v in EVENT_TYPES.items()}


def connect(url: str | None = None) -> Web3:
    """No url -> in-memory test chain with 10 funded accounts. Url -> real node."""
    if url:
        return Web3(Web3.HTTPProvider(url))
    from web3 import EthereumTesterProvider
    return Web3(EthereumTesterProvider())


def compile_contract() -> tuple[list, str]:
    """Compile ModelLedger.sol -> (abi, bytecode). Downloads solc on first run."""
    from solcx import compile_source, install_solc

    install_solc(SOLC_VERSION)
    compiled = compile_source(
        CONTRACT_FILE.read_text(),
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        evm_version="paris",  # widest compatibility across chains / test EVMs
    )
    _, iface = compiled.popitem()
    return iface["abi"], iface["bin"]


class Ledger:
    """High-level API over the deployed contract."""

    def __init__(self, w3: Web3, contract):
        self.w3 = w3
        self.contract = contract

    # ------------------------------------------------------------- deployment
    @classmethod
    def deploy(cls, w3: Web3, deployer: str, abi=None, bytecode=None) -> "Ledger":
        if abi is None or bytecode is None:
            abi, bytecode = compile_contract()
        factory = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = factory.constructor().transact({"from": deployer})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)
        return cls(w3, contract)

    # --------------------------------------------------------------- registry
    def register_issuer(self, admin: str, issuer: str, role: str, name: str) -> None:
        tx = self.contract.functions.registerIssuer(issuer, ROLES[role], name).transact({"from": admin})
        self.w3.eth.wait_for_transaction_receipt(tx)

    def revoke_issuer(self, admin: str, issuer: str) -> None:
        tx = self.contract.functions.revokeIssuer(issuer).transact({"from": admin})
        self.w3.eth.wait_for_transaction_receipt(tx)

    def role_at(self, who: str, timestamp: int) -> str:
        """Role `who` held at `timestamp` ('None' if unregistered or revoked by then)."""
        return ROLE_NAMES[self.contract.functions.roleAt(who, timestamp).call()]

    def issuer_name(self, who: str) -> str:
        return self.contract.functions.issuers(who).call()[1] or "(unregistered)"

    # ----------------------------------------------------------------- events
    def record_event(
        self,
        signer: str,
        artifact_hash: bytes,
        parent_hash: bytes,
        record_hash: bytes,
        commitment_root: bytes,
        phash: int,
        event_type: str,
    ) -> int:
        """Record one provenance step on-chain. Returns the new event id."""
        tx = self.contract.functions.recordEvent(
            artifact_hash, parent_hash, record_hash, commitment_root, phash, EVENT_TYPES[event_type]
        ).transact({"from": signer})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        logs = self.contract.events.EventRecorded().process_receipt(receipt)
        return logs[0]["args"]["id"]

    def get_event(self, event_id: int) -> dict:
        (artifact, parent, record, commitment, phash, etype, signer, ts) = (
            self.contract.functions.getEvent(event_id).call()
        )
        return {
            "id": event_id,
            "artifact_hash": bytes(artifact),
            "parent_hash": bytes(parent),
            "record_hash": bytes(record),
            "commitment_root": bytes(commitment),
            "phash": phash,
            "event_type": EVENT_TYPE_NAMES[etype],
            "signer": signer,
            "timestamp": ts,
        }

    def events_for_artifact(self, artifact_hash: bytes) -> list[dict]:
        ids = self.contract.functions.getEventIdsByArtifact(artifact_hash).call()
        return [self.get_event(i) for i in ids]

    def event_count(self) -> int:
        return self.contract.functions.eventCount().call()

    def verify_artifact(
        self,
        artifact_hash: bytes,
        *,
        content: bytes | None = None,
        private_values=None,
    ):
        """Verify an artifact against all on-chain claims and its history."""
        from provenance import verify_artifact

        return verify_artifact(
            artifact_hash,
            (self.get_event(i) for i in range(self.event_count())),
            self,
            content=content,
            private_values=private_values,
        )
