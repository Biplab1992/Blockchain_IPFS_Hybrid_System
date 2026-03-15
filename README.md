# Blockchain + IPFS Hybrid Certificate Verification System

A decentralized certificate registry where the file and metadata are stored on IPFS and the integrity anchor is stored on Ethereum via `CertificateRegistry.sol`.  
The frontend issues/revokes certificates with the user wallet (MetaMask), while the backend handles pinning, verification APIs, and certificate indexing.

This gives a hybrid model:
- Off-chain: encrypted certificate blob + minimal metadata JSON on IPFS
- On-chain: certificate ID, metadata CID, file CID, file hash, issuer, version/replacement status, revocation status

## Architecture

```text
User (MetaMask)
   |
   | upload PDF
   v
Frontend (React/Vite: app/)
   |                          \
   | POST /api/pin             \ issueCertificate()/revokeCertificate()
   v                            \ (wallet-signed tx)
Backend (Express/TS: backend/)  ---> Ethereum (CertificateRegistry)
   |
   | pin file + metadata
   v
IPFS (Pinata + gateways)

Verification flow:
certId -> backend reads chain -> fetches metadata/encrypted blob from IPFS -> recomputes hash -> VALID/REVOKED/TAMPERED
```

## Prerequisites

- Node.js 20+ (Node 22 recommended)
- npm 10+
- MetaMask (for wallet-native issue/revoke)
- Hardhat (installed from local `contracts/` dependencies)
- Pinata JWT (required for upload/issue flow via `POST /api/pin`)
- Optional for local public verify/pin demo only: Supabase
- Required for auth/RBAC/MoE/institution admin flows: Supabase project URL + service role key
- Optional for testnet deployments: Sepolia RPC + funded deployer wallet + Etherscan key

## Repository Structure

- `app/`: React frontend (wallet-native issue/revoke + verify UI)
- `backend/`: Express API (pinning, verify API, indexer, optional relay mode)
- `contracts/`: Solidity contract + deploy scripts + Hardhat tests

## Module Boundaries

Recent refactoring splits the most reusable cross-cutting concerns into dedicated modules instead of keeping them inside the main entry files:

- Frontend shared helpers: [`app/src/lib/app-core.js`](app/src/lib/app-core.js)
- Frontend public verification/institution pages: [`app/src/pages/PublicPages.jsx`](app/src/pages/PublicPages.jsx)
- Frontend shell and authenticated route composition: [`app/src/App.jsx`](app/src/App.jsx)
- Backend request logging/origin helpers: [`backend/src/server-observability.ts`](backend/src/server-observability.ts)
- Backend IPFS hashing/fetch/pin client: [`backend/src/ipfs-client.ts`](backend/src/ipfs-client.ts)
- Backend PDF verification metadata embedding: [`backend/src/pdf-verification.ts`](backend/src/pdf-verification.ts)
- Backend route wiring, indexers, and relay flows: [`backend/src/server.ts`](backend/src/server.ts)

## Environment Setup

Copy templates and fill values:

```bash
copy app\.env.example app\.env
copy backend\.env.example backend\.env
copy contracts\.env.example contracts\.env
```

Minimum important variables:
- `backend/.env`: `PINATA_JWT`, `FILE_ENCRYPTION_KEY`, `JWT_SECRET`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `RPC_URL`, `CONTRACT_NETWORK_NAME`
- `contracts/.env`: `DEPLOYER_PRIVATE_KEY` only when using raw signer deploy/testnet scripts
- `app/.env`: `VITE_API_BASE_URL`, `VITE_CONTRACT_ADDRESS`, `VITE_CHAIN_ID`, `VITE_RPC_URL`

Local demo notes:
- `PUBLIC_VERIFY_BASE_URL` is optional for local development. Leave it blank unless you want QR codes to point at a public URL.
- `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are optional only if you are testing the public pin/verify flow without auth/RBAC features.
- `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are required if you want `/api/auth/*`, `/api/moe/*`, `/api/institution/*`, invitation flows, or persistent database-backed admin state.

Additional auth variables (`backend/.env`):
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `JWT_ACCESS_TTL_SEC`
- `JWT_REFRESH_TTL_SEC`
- `AUTH_RATE_WINDOW_MS`
- `AUTH_RATE_MAX`

If using Supabase-backed auth/indexer flows, also set:
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

### How To Get These Keys/Values

- `RPC_URL` / `SEPOLIA_RPC_URL`:
  - Create an endpoint from a provider like Infura, Alchemy, or QuickNode.
  - For local dev, use `http://127.0.0.1:8545` from `npx hardhat node`.
- `DEPLOYER_PRIVATE_KEY` / `ISSUER_PRIVATE_KEY`:
  - Use a dedicated wallet for development or testnet only.
  - For local Hardhat node, you can use one of the printed test account private keys.
  - Never use a mainnet wallet private key in local `.env`.
- `PINATA_JWT`:
  - Create a scoped API key in Pinata dashboard and use its JWT token.
  - Keep this server-side only (`backend/.env`), never expose in frontend.
- `FILE_ENCRYPTION_KEY`:
  - Generate 32 random bytes and store them as hex or base64 in `backend/.env`.
  - Example (PowerShell): `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
  - Treat this as a secret. If it changes, previously pinned encrypted files cannot be decrypted with the new key.
- `JWT_SECRET`:
  - Generate a long random secret for backend auth token signing.
  - Example (PowerShell): `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
- `ETHERSCAN_API_KEY`:
  - Create from Etherscan account settings for contract verification.
  - Optional unless you run `npm run verify:sepolia`.
- `VITE_CONTRACT_ADDRESS`:
  - Use the deployed address printed by `contracts/scripts/deploy.ts`.
  - Keep `VITE_CHAIN_ID` and `VITE_RPC_URL` aligned with that network.

## Install Dependencies

```bash
npm install
npm --prefix app install
npm --prefix backend install
npm --prefix contracts install
```

Notes:
- Root `npm install` is needed for root scripts such as `npm run dev` and `npm run dev:all`.
- If you only want to work inside one package, you can install that package on its own.

## Local Development (Hardhat + Frontend + Backend)

### 1. Start local chain

```bash
cd contracts
npx hardhat node
```

### 2. Deploy contract to localhost

In a new terminal:

```bash
cd contracts
npx hardhat run scripts/deploy.ts --network localhost
```

Update `app/.env` and/or `backend/.env` with the deployed contract address:
- `VITE_CONTRACT_ADDRESS=...`
- `CERTIFICATE_REGISTRY_ADDRESS=...` (optional if using `contracts/deployments.json`)

Notes:
- The frontend needs `VITE_CONTRACT_ADDRESS` set correctly.
- The backend can usually read the address from `contracts/deployments.json`, so `CERTIFICATE_REGISTRY_ADDRESS` is optional for local deploys.

### 3. Decide which wallet will issue certificates

The contract deployer is automatically added to the issuer allowlist at construction time.

Simplest local option:
- Import the local Hardhat deployer account into MetaMask and use that wallet to issue/revoke.

If you want to use a different MetaMask wallet:
1. Put the wallet address into `contracts/.env` as `ISSUER_ADDRESS=0x...`
2. Run:

```bash
cd contracts
npx hardhat run scripts/set-issuer.ts --network localhost
```

Without this step, issuance from a non-authorized wallet will revert with `Issuer not authorised`.

### 4. Start backend

```bash
cd backend
npm run dev
```

### 5. Start frontend

```bash
cd app
npm run dev
```

Open `http://localhost:5173`.

Optional root shortcuts:
- `npm run dev` starts backend + frontend together after your chain/contract are already ready.
- `npm run dev:all` is a Windows PowerShell convenience script that starts chain, deploys, backend, and frontend together.
- `npm run dev:all` does not auto-authorize a different MetaMask wallet; you still need the `set-issuer.ts` step if you are not using the deployer wallet.

## Public QR Verification (Any Network)

To generate QR codes that work outside your local network:

1. Deploy frontend publicly (example: `https://verify.yourdomain.com`)
2. Deploy backend publicly (example: `https://api.yourdomain.com`)
3. Set:
   - `backend/.env`
     - `PUBLIC_VERIFY_BASE_URL=https://verify.yourdomain.com/verify`
     - `CORS_ORIGINS=https://verify.yourdomain.com`
   - `app/.env`
     - `VITE_API_BASE_URL=https://api.yourdomain.com`
4. Restart/redeploy backend and frontend.
5. Issue new certificates. Newly generated QR codes will contain the public verify URL.

Notes:
- Old QR codes keep their original URL and will not change retroactively.
- If `PUBLIC_VERIFY_BASE_URL` is not set, backend may emit a local/LAN URL depending on request origin.

## Run Tests

```bash
npm test
```

Default local validation covers:
- owner-only issuer management
- backend file-envelope encryption/unit checks
- frontend verify-page UI test coverage
- frontend production-build smoke check
- authorized issuer issuance rules
- revoke permission boundaries + double revoke prevention
- replacement/version rules including same-issuer enforcement
- event emission correctness

Environment-dependent backend integration checks are separate:

```bash
npm run test:integration
```

Notes:
- `npm run test:integration` requires `TEST_API_BASE` and supporting backend test env to be configured.
- `npm --prefix backend run test:e2e-full` exercises the authenticated backend flow and, when `TEST_FULL_CHAIN_E2E=1`, the on-chain issue/verify path using PDF uploads.
- `npm --prefix app run test:ui` runs the Vitest/RTL frontend tests directly.

## Supabase Database Setup

Run the SQL in [`backend/supabase/schema.sql`](backend/supabase/schema.sql) before using any Supabase-backed features.

The schema creates both index tables and auth/admin tables, including:
- `certificates`
- `indexer_state`
- `issuer_status`
- `issuer_events`
- `users`
- `institutions`
- `institution_users`
- `invitations`
- `wallet_bindings`
- `refresh_tokens`
- `password_reset_tokens`
- `authorization_requests`
- `audit_logs`

Notes:
- If you only want the local public pin/verify flow, you can leave Supabase unset.
- If you want auth, MoE admin, institution admin, invitations, password reset, or database-backed audit flows, Supabase is required.
- Issuer authorization itself remains on-chain. Supabase stores index/audit/application state around those on-chain events.

## Auth + RBAC

Roles:
- `MOE_ADMIN`
- `INSTITUTION_ADMIN`
- `INDIVIDUAL`

These routes require `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and the schema from [`backend/supabase/schema.sql`](backend/supabase/schema.sql).

Core auth endpoints:
- `POST /api/auth/register` (individual)
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/invitations/accept` (institution invite completion)

MoE routes:
- `POST /api/moe/institutions`
- `PATCH /api/moe/institutions/:id/status`
- `DELETE /api/moe/institutions/:id`
- `GET /api/moe/institutions`
- `POST /api/moe/institutions/:id/resend-invite`

Invite email delivery (Resend):
- Set backend env:
  - `RESEND_API_KEY`
  - `RESEND_FROM_EMAIL` (must be a verified sender/domain in Resend)
  - optional `INVITE_EMAIL_SUBJECT_PREFIX`
- When MoE creates/resends institution invites, backend now attempts to send email directly via Resend.
- API response includes:
  - `emailSent: true|false`
  - `emailError` (when sending failed)
  - `inviteUrl` fallback (for manual copy if needed)

Institution routes:
- `GET /api/institution/profile`
- `POST /api/institution/wallet/nonce`
- `POST /api/institution/wallet/verify-signature`
- `POST /api/certificates/issue` (wallet-native preflight + audit)
- `POST /api/certificates/revoke` (wallet-native preflight + audit)

Security notes:
- Passwords are hashed with bcrypt.
- Refresh tokens are stored hashed.
- Issuance/revoke gate checks institution status, wallet binding, wallet==issuer_wallet, and on-chain `authorizedIssuers`.
- `GET /api/verify/:certId` remains public.

## End-to-End Demo Flow

1. Open `/issue` in frontend.
2. Connect MetaMask and switch to configured chain.
3. Upload PDF.
4. Frontend calls `POST /api/pin`.
5. Backend encrypts the processed PDF, pins the encrypted blob + minimal metadata to IPFS, and returns:
   - `fileCid`
   - `metadataCid`
   - `fileHash` (sha256 of the encrypted blob)
6. Frontend wallet calls `issueCertificate(certId, metadataCid, fileCid, fileHash, version, replacesCertId)`.
7. Contract stores on-chain certificate anchor.
8. Open `/verify`, enter `certId`.
9. Backend reads on-chain record, fetches metadata/encrypted blob from IPFS, recomputes the encrypted blob hash, and returns `VALID`, `REVOKED`, or `TAMPERED`.

## Notes

- Default architecture is wallet-native issuance/revocation.
- Backend relay transaction routes exist but are disabled by default unless:
  - `ENABLE_RELAY_TX_MODE=true` in `backend/.env`.
- Never commit real `.env` files or secrets.
