// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CertificateRegistry {
    address public owner;

    struct Certificate {
        string cid;
        bytes32 fileHash;
        address issuer;
        uint256 issuedAt;
        bool revoked;
        bool exists;
    }

    mapping(string => Certificate) private certificates;

    event CertificateIssued(
        string certId,
        string cid,
        bytes32 fileHash,
        address issuer,
        uint256 issuedAt
    );

    event CertificateRevoked(string certId, address issuer, uint256 revokedAt);

    constructor() {
        owner = msg.sender;
    }

    function issueCertificate(
        string calldata certId,
        string calldata cid,
        bytes32 fileHash
    ) external {
        require(!certificates[certId].exists, "Certificate already exists");

        certificates[certId] = Certificate({
            cid: cid,
            fileHash: fileHash,
            issuer: msg.sender,
            issuedAt: block.timestamp,
            revoked: false,
            exists: true
        });

        emit CertificateIssued(certId, cid, fileHash, msg.sender, block.timestamp);
    }

    function revokeCertificate(string calldata certId) external {
        require(certificates[certId].exists, "Certificate not found");
        require(
            msg.sender == certificates[certId].issuer || msg.sender == owner,
            "Not authorised"
        );

        certificates[certId].revoked = true;
        emit CertificateRevoked(certId, msg.sender, block.timestamp);
    }

    function getCertificate(string calldata certId)
        external
        view
        returns (string memory, bytes32, address, uint256, bool, bool)
    {
        Certificate memory c = certificates[certId];
        return (c.cid, c.fileHash, c.issuer, c.issuedAt, c.revoked, c.exists);
    }
}
