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
```

## Routes

- `/issue` protected issue flow (wallet sign-in + JWT + upload PDF + issue)
- `/verify` public verification flow by `certId`
