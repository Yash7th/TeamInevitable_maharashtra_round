# ModelLedger: Web3 AI Provenance Tracker

**ModelLedger** is a decentralized provenance and tamper-verification system for Generative AI artifacts (images, audio, prompt pipelines, code, and fine-tuned models) featuring a **Zero-Knowledge Cryptographic Provenance Vault**.

It connects a **Streamlit** frontend to a local in-memory **Ethereum test chain (`web3.py` + `eth-tester`)** with dynamic smart contract compilation via **`py-solc-x`**.

---

## Cryptographic Vault Lock and Key Mechanism

When registering an artifact:
1. **Key Generation**: The exact SHA-256 digest (`32 bytes / 256 bits`) of the authentic image or artifact file serves as the **cryptographic lock key**.
2. **On-Chain Sealing**: The original generation prompt is encrypted using **AES-256-CBC** with the image hash as the symmetric key, and the ciphertext is stored in the [ModelLedger.sol](file:///ModelLedger.sol) smart contract mapping.
3. **Tamper-Locked Verification**:
   - When any user uploads a file to verify, the system derives the SHA-256 key from that file.
   - **Authentic Image**: The key matches the on-chain ledger, **unlocking** and displaying:
     - **Model Origin**: *"This image was generated using the `<Model Name>` model."*
     - **Prompt Vault**: *"This prompt was used to create this image: `<Decrypted Prompt>`"*
   - **Tampered or Modified Image**: If even a single pixel or byte is altered, the derived hash changes. The smart contract query fails, the ciphertext cannot be decrypted, and the user receives a **Tamper Alert** with all model and prompt metadata strictly blocked and locked.

---

## Project Structure

```text
model-ledger/
├── app.py                # Main Streamlit UI, Web3 logic, and AES-256 Vault Encryption
├── ModelLedger.sol       # Solidity smart contract storing encrypted prompt and lineage
├── requirements.txt      # Python dependencies (streamlit, web3[tester], py-solc-x, pycryptodome)
└── README.md             # Project documentation and run instructions
```

---

## Quickstart Guide

### Option A: One-Click Launcher (Windows)
Double-click [run.bat](file:///run.bat) in the root or in the `model-ledger/` directory.

### Option B: Manual Startup

```bash
cd model-ledger
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501` to access the application.

---

## Smart Contract Specification

- **Contract Name**: `ModelLedger`
- **Compiler**: `solc 0.8.20`
- **License**: MIT

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ModelLedger {
    enum TrustTier { SelfAsserted, Trusted, Unverifiable }
    struct Artifact {
        bytes32 imageHash;
        bytes32 promptHash;
        string encryptedPrompt; // Encrypted with imageHash as the AES-256 key
        string modelName;
        bytes32 parentHash;
        TrustTier trustTier;
        address publisher;
        uint256 timestamp;
    }
    mapping(bytes32 => Artifact) public ledger;
    mapping(bytes32 => bool) public isRegistered;

    function registerArtifact(
        bytes32 _img,
        bytes32 _promptHash,
        string memory _encryptedPrompt,
        string memory _model,
        bytes32 _parent,
        TrustTier _tier
    ) public {
        require(!isRegistered[_img], "Exists");
        ledger[_img] = Artifact(
            _img,
            _promptHash,
            _encryptedPrompt,
            _model,
            _parent,
            _tier,
            msg.sender,
            block.timestamp
        );
        isRegistered[_img] = true;
    }

    function verifyArtifact(bytes32 _img) public view returns (
        bool,
        string memory,
        string memory,
        bytes32,
        TrustTier,
        address,
        uint256
    ) {
        if (!isRegistered[_img]) return (false, "", "", bytes32(0), TrustTier.Unverifiable, address(0), 0);
        Artifact memory a = ledger[_img];
        return (true, a.modelName, a.encryptedPrompt, a.parentHash, a.trustTier, a.publisher, a.timestamp);
    }
}
```
