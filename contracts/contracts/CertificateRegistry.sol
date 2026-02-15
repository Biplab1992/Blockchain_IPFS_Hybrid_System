// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CertificateRegistry {
    address public owner;
    mapping(address => bool) public authorizedIssuers;

    struct Certificate {
        string metadataCid;
        string fileCid;
        bytes32 fileHash;
        address issuer;
        uint256 version;
        string replacesCertId;
        uint256 issuedAt;
        bool revoked;
        bool exists;
    }

    mapping(string => Certificate) private certificates;

    event CertificateIssued(
        string indexed certId,
        string cid,
        address indexed issuer,
        uint256 version,
        string replacesCertId,
        uint256 issuedAt
    );

    event CertificateRevoked(string indexed certId, address indexed issuer, uint256 revokedAt);
    event IssuerAuthorizationUpdated(address indexed issuer, bool allowed);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorizedIssuer() {
        require(authorizedIssuers[msg.sender], "Issuer not authorised");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true;
        emit IssuerAuthorizationUpdated(msg.sender, true);
    }

    function setIssuer(address issuer, bool allowed) external onlyOwner {
        require(issuer != address(0), "Invalid issuer");
        authorizedIssuers[issuer] = allowed;
        emit IssuerAuthorizationUpdated(issuer, allowed);
    }

    function issueCertificate(
        string calldata certId,
        string calldata metadataCid,
        string calldata fileCid,
        bytes32 fileHash,
        uint256 version,
        string calldata replacesCertId
    ) external onlyAuthorizedIssuer {
        require(bytes(certId).length > 0, "certId required");
        require(!certificates[certId].exists, "Certificate already exists");
        require(bytes(metadataCid).length > 0, "metadataCid required");
        require(bytes(fileCid).length > 0, "fileCid required");
        require(version > 0, "version must be >= 1");

        bool isReplacement = bytes(replacesCertId).length > 0;
        if (isReplacement) {
            require(version > 1, "replacement version must be > 1");
            require(certificates[replacesCertId].exists, "replaced certificate not found");
            require(certificates[replacesCertId].revoked, "replaced certificate must be revoked");
        } else {
            require(version == 1, "new certificate must start at version 1");
        }

        certificates[certId] = Certificate({
            metadataCid: metadataCid,
            fileCid: fileCid,
            fileHash: fileHash,
            issuer: msg.sender,
            version: version,
            replacesCertId: replacesCertId,
            issuedAt: block.timestamp,
            revoked: false,
            exists: true
        });

        emit CertificateIssued(
            certId,
            metadataCid,
            msg.sender,
            version,
            replacesCertId,
            block.timestamp
        );
    }

    function revokeCertificate(string calldata certId) external onlyAuthorizedIssuer {
        require(certificates[certId].exists, "Certificate not found");

        certificates[certId].revoked = true;
        emit CertificateRevoked(certId, msg.sender, block.timestamp);
    }

    function getCertificate(string calldata certId)
        external
        view
        returns (string memory, string memory, bytes32, address, uint256, string memory, uint256, bool, bool)
    {
        Certificate memory c = certificates[certId];
        return (
            c.metadataCid,
            c.fileCid,
            c.fileHash,
            c.issuer,
            c.version,
            c.replacesCertId,
            c.issuedAt,
            c.revoked,
            c.exists
        );
    }
}
