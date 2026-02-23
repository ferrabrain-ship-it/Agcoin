---
name: agcoin-miner
description: "Mine AGCOIN by solving AI challenges on Base. Use when the user wants to mine AGCOIN, earn mining credits, or claim epoch rewards."
metadata: { "openclaw": { "emoji": "⛏", "requires": { "env": ["BANKR_API_KEY"], "skills": ["bankr"] } } }
---

# AGCOIN Miner

Mine AGCOIN by solving deterministic natural language challenges. The coordinator returns pre-encoded calldata; submit transactions via Bankr.

## Prerequisites

1. `BANKR_API_KEY` with write access.
2. Base wallet funded with ETH for gas.
3. AGCOIN balance tier:
   - `>= 25,000,000` => 1 credit
   - `>= 50,000,000` => 2 credits
   - `>= 100,000,000` => 3 credits

## Required env

- `BANKR_API_KEY` (required)
- `COORDINATOR_URL` (default: your Railway URL, e.g. `https://your-coordinator.up.railway.app`)
- `CHAIN_ID` (default: `8453`)

## Core flow

1. Resolve wallet from Bankr (`GET /agent/me`).
2. Check balances (`POST /agent/prompt` -> "what are my balances on base?").
3. If needed, swap ETH to AGCOIN using Bankr prompt:
   - `swap $X of ETH to <AGCOIN_TOKEN_ADDRESS> on base`
4. Auth handshake:
   - `POST /v1/auth/nonce`
   - sign with `POST /agent/sign`
   - `POST /v1/auth/verify`
5. Mining loop:
   - `GET /v1/challenge?miner=...&nonce=...` (Bearer token)
   - Solve and produce one-line artifact
   - `POST /v1/submit` with same nonce
   - Submit returned tx via `POST /agent/submit`
6. Claim flow:
   - `GET /v1/epoch`
   - `GET /v1/claim-calldata?epochs=...`
   - submit tx via `POST /agent/submit`

## Bankr rules

- Use `POST /agent/prompt` only for natural-language actions (balances/swap/bridge).
- Use `POST /agent/submit` for all contract interactions (`submitReceipt`, `claim`).

## Error handling

- Retry coordinator on `429`, `5xx`, timeouts with backoff.
- Re-auth on `401` from challenge/submit.
- On `pass:false`, fetch a new challenge (do not reuse same one).

## AGCOIN token

Set AGCOIN token address before production usage:

- `AGCOIN_TOKEN_ADDRESS=0xA1A23a4F55f106e61885e1C007EcAE7493c7fba3`
