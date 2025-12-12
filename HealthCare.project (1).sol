// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "https://cdn.jsdelivr.net/npm/@openzeppelin/contracts@4.9.3/access/AccessControl.sol";

contract HealthRecords is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE");
    bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");

    struct Record {
        bytes32 id;
        address provider;
        address patient;
        bytes32 recordHash; // hash of medical data (e.g., keccak256)
        string ipfsCid;     // optional IPFS CID
        uint256 timestamp;
    }

    // recordId => Record
    mapping(bytes32 => Record) public records;
    // recordId => grantee => bool
    mapping(bytes32 => mapping(address => bool)) public accessList;

    event ProviderRegistered(address indexed provider);
    event PatientRegistered(address indexed patient);
    event RecordSubmitted(bytes32 indexed recordId, address indexed provider, address indexed patient, uint256 timestamp);
    event AccessGranted(bytes32 indexed recordId, address indexed grantee);
    event AccessRevoked(bytes32 indexed recordId, address indexed grantee);

    constructor(address admin) {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(ADMIN_ROLE, admin);
    }

    // ADMIN functions
    function registerProvider(address provider) external onlyRole(ADMIN_ROLE) {
        grantRole(PROVIDER_ROLE, provider);
        emit ProviderRegistered(provider);
    }

    function registerPatient(address patient) external onlyRole(ADMIN_ROLE) {
        grantRole(PATIENT_ROLE, patient);
        emit PatientRegistered(patient);
    }

    // Provider submits a record for a patient
    function submitRecord(address patient, bytes32 recordHash, string calldata ipfsCid) external onlyRole(PROVIDER_ROLE) returns (bytes32) {
        require(hasRole(PATIENT_ROLE, patient), "Patient not registered");
        // record id derived from provider + patient + timestamp + hash
        bytes32 recordId = keccak256(abi.encodePacked(msg.sender, patient, recordHash, block.timestamp));
        records[recordId] = Record({
            id: recordId,
            provider: msg.sender,
            patient: patient,
            recordHash: recordHash,
            ipfsCid: ipfsCid,
            timestamp: block.timestamp
        });
        // by default, patient and provider have access
        accessList[recordId][patient] = true;
        accessList[recordId][msg.sender] = true;

        emit RecordSubmitted(recordId, msg.sender, patient, block.timestamp);
        return recordId;
    }

    // Patient grants access to another address (doctor / auditor)
    function grantAccess(bytes32 recordId, address grantee) external {
        Record storage r = records[recordId];
        require(r.patient != address(0), "Record not exist");
        require(msg.sender == r.patient, "Only patient can grant access");
        accessList[recordId][grantee] = true;
        emit AccessGranted(recordId, grantee);
    }

    function revokeAccess(bytes32 recordId, address grantee) external {
        Record storage r = records[recordId];
        require(r.patient != address(0), "Record not exist");
        require(msg.sender == r.patient, "Only patient can revoke");
        accessList[recordId][grantee] = false;
        emit AccessRevoked(recordId, grantee);
    }

    // viewers check
    function hasAccess(bytes32 recordId, address who) public view returns (bool) {
        return accessList[recordId][who];
    }

    function getRecordMeta(bytes32 recordId) external view returns (
        address provider,
        address patient,
        bytes32 recordHash,
        string memory ipfsCid,
        uint256 timestamp
    ) {
        Record storage r = records[recordId];
        require(r.patient != address(0), "Record not exist");
        require(accessList[recordId][msg.sender] || msg.sender == r.patient || hasRole(ADMIN_ROLE, msg.sender), "No access");
        return (r.provider, r.patient, r.recordHash, r.ipfsCid, r.timestamp);
    }
}
