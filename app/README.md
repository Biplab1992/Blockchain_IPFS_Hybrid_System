# Certificate Demo UI

## Run

```bash
npm install
npm run dev
```

## Config

Set optional API base URL:

```bash
VITE_API_BASE_URL=http://localhost:5050
VITE_CONTRACT_ADDRESS=0x...
VITE_RPC_URL=http://127.0.0.1:8545
VITE_CHAIN_ID=31337
```

## Routes

- `/issue` protected issue flow (wallet sign-in + JWT + upload PDF + issue)
- `/verify` public verification flow by `certId`
