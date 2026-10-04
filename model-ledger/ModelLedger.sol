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
