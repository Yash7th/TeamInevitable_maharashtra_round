// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ModelLedger
/// @notice Registry of trusted AI issuers + append-only log of provenance events.
/// @dev Design rule: ANYONE can record an event (so self-asserted claims can exist
///      on-chain), but only admin-registered addresses count as TRUSTED issuers.
///      The contract does NOT judge a chain; the off-chain verifier does that by
///      reading roles and events. The contract's job is an honest, timestamped record.
contract ModelLedger {
    enum Role { None, Generator, Editor, Publisher }
    enum EventType { Generate, Transform, Publish }

    struct Issuer {
        Role role;
        string name;
        uint64 registeredAt;
        uint64 revokedAt; // 0 = not revoked
    }

    struct ProvenanceEvent {
        bytes32 artifactHash;   // SHA-256 of the output file produced by this step
        bytes32 parentHash;     // SHA-256 of the input artifact (0x0 for a Generate step)
        bytes32 recordHash;     // hash of the full off-chain provenance record (JSON)
        bytes32 commitmentRoot; // salted commitment / Merkle root of PRIVATE data (prompt etc.)
        uint64 pHash;           // 64-bit perceptual hash (soft binding after resize/re-encode)
        EventType eventType;
        address signer;         // who recorded it (msg.sender)
        uint64 timestamp;       // block time, so claims can't be backdated
    }

    address public admin;
    mapping(address => Issuer) public issuers;
    ProvenanceEvent[] private _events;
    mapping(bytes32 => uint256[]) private _eventIdsByArtifact;

    event IssuerRegistered(address indexed issuer, Role role, string name);
    event IssuerRevoked(address indexed issuer, uint64 at);
    event EventRecorded(
        uint256 indexed id,
        bytes32 indexed artifactHash,
        bytes32 indexed parentHash,
        address signer,
        EventType eventType
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // ---------------------------------------------------------------- registry

    function registerIssuer(address issuer, Role role, string calldata name) external onlyAdmin {
        require(role != Role.None, "role required");
        require(issuers[issuer].role == Role.None, "already registered");
        issuers[issuer] = Issuer(role, name, uint64(block.timestamp), 0);
        emit IssuerRegistered(issuer, role, name);
    }

    function revokeIssuer(address issuer) external onlyAdmin {
        Issuer storage i = issuers[issuer];
        require(i.role != Role.None, "not registered");
        require(i.revokedAt == 0, "already revoked");
        i.revokedAt = uint64(block.timestamp);
        emit IssuerRevoked(issuer, i.revokedAt);
    }

    /// @notice The role `who` held at time `ts` (Role.None if unregistered, not yet
    ///         registered, or already revoked). The verifier uses this so a key that is
    ///         revoked later does not retroactively invalidate old, honest records.
    function roleAt(address who, uint64 ts) public view returns (Role) {
        Issuer memory i = issuers[who];
        if (i.role == Role.None) return Role.None;
        if (ts < i.registeredAt) return Role.None;
        if (i.revokedAt != 0 && ts >= i.revokedAt) return Role.None;
        return i.role;
    }

    // ------------------------------------------------------------------ events

    function recordEvent(
        bytes32 artifactHash,
        bytes32 parentHash,
        bytes32 recordHash,
        bytes32 commitmentRoot,
        uint64 pHash,
        EventType eventType
    ) external returns (uint256 id) {
        require(artifactHash != bytes32(0), "artifactHash required");
        id = _events.length;
        _events.push(
            ProvenanceEvent(
                artifactHash,
                parentHash,
                recordHash,
                commitmentRoot,
                pHash,
                eventType,
                msg.sender,
                uint64(block.timestamp)
            )
        );
        _eventIdsByArtifact[artifactHash].push(id);
        emit EventRecorded(id, artifactHash, parentHash, msg.sender, eventType);
    }

    function eventCount() external view returns (uint256) {
        return _events.length;
    }

    function getEvent(uint256 id) external view returns (ProvenanceEvent memory) {
        require(id < _events.length, "no such event");
        return _events[id];
    }

    /// @notice All events that produced this exact artifact hash. More than one entry
    ///         (especially with different signers/parents) is a CONFLICT the verifier flags.
    function getEventIdsByArtifact(bytes32 artifactHash) external view returns (uint256[] memory) {
        return _eventIdsByArtifact[artifactHash];
    }
}
