# AGCOIN Coordinator Backend

Backend API for AGCOIN mining flow (auth, challenge, submit, epoch info, claim calldata), compatible with the `BotcoinMining` contract interface.

## Current on-chain config

- Mining contract: `0xA27A9af83E2124Bcb10FB56A62Dd5C96c9867c52`
- Coordinator signer (provided): `0xbb34256BC4d0234393e62fc8ac3e237416fC16dc`
- AGCOIN token: `0xA1A23a4F55f106e61885e1C007EcAE7493c7fba3`

## Quick start (local)

```bash
cp .env.example .env
# fill RPC_URL and COORDINATOR_SIGNER_PRIVATE_KEY
npm install
npm run dev
```

Health check:

```bash
curl -s http://localhost:3000/health
```

## Required env vars

- `RPC_URL`: Base RPC endpoint
- `MINING_CONTRACT_ADDRESS`: default prefilled with your CA
- `COORDINATOR_SIGNER_PRIVATE_KEY`: private key of the backend signer

## Useful optional env vars

- `AGCOIN_TOKEN_ADDRESS`: if set, `/v1/token` uses this address; otherwise it reads `botcoinToken()` from contract
- `GENESIS_TIMESTAMP`: override contract value if needed
- `EPOCH_DURATION_SECONDS`: `86400` mainnet, `1800` test setup

## API

- `GET /health`
- `GET /v1/token`
- `GET /v1/epoch`
- `POST /v1/auth/nonce`
- `POST /v1/auth/verify`
- `GET /v1/challenge?miner=0x...&nonce=...` (Bearer required)
- `POST /v1/submit` (Bearer required)
- `GET /v1/claim-calldata?epochs=20,21`
- `GET /v1/credits?miner=0x...`

## Railway deploy

1. Create a new Railway project from this repo.
2. Add env vars from `.env.example`.
3. Set `RPC_URL` and `COORDINATOR_SIGNER_PRIVATE_KEY` first.
4. Deploy (Railway uses `railway.json`, command: `npm run start`).
5. Verify:

```bash
curl -s https://<your-railway-domain>/health
```

## Your coordinator URL

- You should use your own Railway domain as `COORDINATOR_URL` (example: `https://your-coordinator.up.railway.app`).
- Do not use `https://coordinator.agentmoney.net` unless you control that backend.
- Optional custom domain:
1. In Railway service settings, add custom domain (example: `coordinator.agcoin.xyz`).
2. Create DNS `CNAME` from `coordinator.agcoin.xyz` to Railway target.
3. Wait for TLS provisioning in Railway.
4. Set `COORDINATOR_URL=https://coordinator.agcoin.xyz` in miner/client env.

## Important note

This scaffold is production-oriented for API shape and EIP-712 signing compatibility, but challenge generation/verifier logic is currently minimal and deterministic by design. Replace `buildChallenge()` and solver verification logic in `src/index.ts` with your final challenge engine.
