# Contracts

## Contract Purpose

`CertificateRegistry.sol` is the on-chain trust anchor for certificates issued in this project.
It stores immutable certificate metadata references and integrity data (CIDs + file hash), tracks revocation state, and enforces issuer governance rules for issuance, replacement, and revocation.

The contract is designed to keep large files off-chain (IPFS) while preserving verifiable integrity and auditability on-chain.

## Main Contract

- `contracts/contracts/CertificateRegistry.sol`

## Key Functions

- `setIssuer(address issuer, bool allowed)`
  - Owner-only function to grant/revoke issuer authorization.

- `issueCertificate(string certId, string metadataCid, string fileCid, bytes32 fileHash, uint256 version, string replacesCertId)`
  - Issuer-only certificate issuance.
  - Enforces version/replacement rules:
    - New certs must start at `version == 1`.
    - Replacements require `version > 1`.
    - Replaced certificate must exist and be revoked.
    - Replacement must be issued by the same original issuer.

- `revokeCertificate(string certId)`
  - Can be called only by:
    - contract `owner`, or
    - the certificate’s original `issuer`.
  - Prevents double-revocation.

- `getCertificate(string certId)`
  - Returns certificate record fields.
  - Reverts if the certificate does not exist.

## Key Events

- `CertificateIssued(string indexed certId, string metadataCid, address indexed issuer, uint256 version, string replacesCertId, uint256 issuedAt)`
- `CertificateRevoked(string indexed certId, address indexed issuer, uint256 revokedAt)`
- `IssuerAuthorizationUpdated(address indexed issuer, bool allowed)`

## Access Control Model

- Owner role:
  - Contract deployer is `owner`.
  - Only owner can manage issuer allowlist (`setIssuer`).
  - Owner can revoke any certificate.

- Authorized issuer role:
  - `issueCertificate` requires `authorizedIssuers[msg.sender] == true`.
  - For replacement certificates, issuer must match the issuer of the replaced cert.

- Certificate-level revoke authorization:
  - `revokeCertificate` is not merely role-based.
  - It enforces certificate ownership semantics:
    - only contract owner or original certificate issuer can revoke.

## Run Tests

From `contracts/`:

```bash
npm test
```

Current test coverage includes:
- owner-only issuer management
- authorized issuer issuance
- revoke permission boundaries and double-revoke protection
- replacement/version governance rules
- event emission correctness
