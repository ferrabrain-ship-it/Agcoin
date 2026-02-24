import cors from "cors";
import dotenv from "dotenv";
import express, { type Request, type Response, type NextFunction } from "express";
import { Pool } from "pg";
import { createClient, type RedisClientType } from "redis";
import {
  Contract,
  Interface,
  JsonRpcProvider,
  Wallet,
  getAddress,
  getBytes,
  hashMessage,
  keccak256,
  randomBytes,
  recoverAddress,
  toUtf8Bytes,
  verifyMessage
} from "ethers";
import { z } from "zod";

dotenv.config();

const config = {
  port: Number(process.env.PORT ?? 3000),
  rpcUrl: process.env.RPC_URL ?? "",
  chainId: Number(process.env.CHAIN_ID ?? 8453),
  miningContractAddress: process.env.MINING_CONTRACT_ADDRESS ?? "",
  coordinatorSignerPrivateKey: process.env.COORDINATOR_SIGNER_PRIVATE_KEY ?? "",
  epochDurationSeconds: Number(process.env.EPOCH_DURATION_SECONDS ?? 86400),
  authNonceTtlSeconds: Number(process.env.AUTH_NONCE_TTL_SECONDS ?? 300),
  authTokenTtlSeconds: Number(process.env.AUTH_TOKEN_TTL_SECONDS ?? 900),
  challengeTtlSeconds: Number(process.env.CHALLENGE_TTL_SECONDS ?? 1800),
  minerLockTtlSeconds: Number(process.env.MINER_LOCK_TTL_SECONDS ?? 20),
  eip712Name: process.env.EIP712_NAME ?? "AgcoinMining",
  eip712Version: process.env.EIP712_VERSION ?? "1",
  rulesVersion: Number(process.env.RULES_VERSION ?? 1),
  agcoinTokenAddress: process.env.AGCOIN_TOKEN_ADDRESS,
  genesisTimestampEnv: process.env.GENESIS_TIMESTAMP,
  redisUrl: process.env.REDIS_URL,
  databaseUrl: process.env.DATABASE_URL,
  adminApiKey: process.env.ADMIN_API_KEY
};

if (!config.rpcUrl) throw new Error("Missing RPC_URL");
if (!config.miningContractAddress) throw new Error("Missing MINING_CONTRACT_ADDRESS");
if (!config.coordinatorSignerPrivateKey) throw new Error("Missing COORDINATOR_SIGNER_PRIVATE_KEY");

const provider = new JsonRpcProvider(config.rpcUrl, config.chainId);
const coordinatorSigner = new Wallet(config.coordinatorSignerPrivateKey, provider);

const miningAbi = [
  "function nextIndex(address miner) view returns (uint64)",
  "function lastReceiptHash(address miner) view returns (bytes32)",
  "function tier1Balance() view returns (uint256)",
  "function tier2Balance() view returns (uint256)",
  "function tier3Balance() view returns (uint256)",
  "function currentEpoch() view returns (uint64)",
  "function genesisTimestamp() view returns (uint256)",
  "function agcoinToken() view returns (address)",
  "function epochCommit(uint64) view returns (bytes32)",
  "function claim(uint64[] epochIds)",
  "function submitReceipt(uint64,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint128,uint32,bytes)"
];

const erc20Abi = ["function balanceOf(address account) view returns (uint256)"];

const mining = new Contract(config.miningContractAddress, miningAbi, provider);
const miningInterface = new Interface(miningAbi);

type NonceRecord = {
  miner: string;
  message: string;
  expiresAt: number;
};

type TokenRecord = {
  miner: string;
  expiresAt: number;
};

type ChallengePayload = {
  challengeId: string;
  epochId: number;
  nonce: string;
  miner: string;
  doc: string;
  questions: string[];
  constraints: string[];
  companies: string[];
  expectedArtifact: string;
  creditsPerSolve: number;
  createdAt: number;
};

const authNonces = new Map<string, NonceRecord>();
const authTokens = new Map<string, TokenRecord>();
const challenges = new Map<string, ChallengePayload>();
const creditsBook = new Map<string, number>();
const localLocks = new Map<string, { token: string; expiresAt: number }>();

type RequestMetric = {
  count: number;
  errors: number;
  totalDurationMs: number;
};

const metricsState = {
  processStartedAt: new Date().toISOString(),
  requestsTotal: 0,
  requestErrors: 0,
  endpoint: new Map<string, RequestMetric>()
};

const redis: RedisClientType | null = config.redisUrl ? createClient({ url: config.redisUrl }) : null;
const pgPool: Pool | null = config.databaseUrl ? new Pool({ connectionString: config.databaseUrl }) : null;

let cachedGenesisTimestamp: bigint | null = config.genesisTimestampEnv ? BigInt(config.genesisTimestampEnv) : null;
let cachedTokenAddress: string | null = config.agcoinTokenAddress ?? null;

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function randomHex(bytesCount: number): string {
  return Buffer.from(randomBytes(bytesCount)).toString("hex");
}

function hashText(input: string): string {
  return keccak256(toUtf8Bytes(input));
}

function parseNonceFromMessage(message: string): string | null {
  const match = message.match(/^Nonce:\s*(\S+)$/m);
  return match?.[1] ?? null;
}

function normalizeSignatureHex(signature: string): string {
  let value = signature.trim();
  if (
    (value.startsWith("\"") && value.endsWith("\"")) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1).trim();
  }
  if (!value.startsWith("0x")) value = `0x${value}`;
  return value;
}

function bytesToHexNoPrefix(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function padTo32BytesHex(hexNoPrefix: string): string | null {
  const normalized = hexNoPrefix.replace(/^0+/, "") || "0";
  if (normalized.length > 64) return null;
  return normalized.padStart(64, "0");
}

function readDerLen(bytes: Uint8Array, offset: number): { length: number; next: number } | null {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  if ((first & 0x80) === 0) {
    return { length: first, next: offset + 1 };
  }

  const octets = first & 0x7f;
  if (octets === 0 || octets > 2) return null;
  if (offset + 1 + octets > bytes.length) return null;

  let length = 0;
  for (let i = 0; i < octets; i += 1) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  return { length, next: offset + 1 + octets };
}

function parseDerEcdsa(signatureBytes: Uint8Array): { r: string; s: string } | null {
  // ASN.1 DER: 30 <len> 02 <r-len> <r> 02 <s-len> <s>
  if (signatureBytes.length < 8 || signatureBytes[0] !== 0x30) return null;

  const seq = readDerLen(signatureBytes, 1);
  if (!seq) return null;
  let cursor = seq.next;
  if (cursor + seq.length !== signatureBytes.length) return null;

  if (cursor >= signatureBytes.length || signatureBytes[cursor] !== 0x02) return null;
  const rLenInfo = readDerLen(signatureBytes, cursor + 1);
  if (!rLenInfo) return null;
  cursor = rLenInfo.next;
  if (cursor + rLenInfo.length > signatureBytes.length) return null;
  const rRaw = signatureBytes.slice(cursor, cursor + rLenInfo.length);
  cursor += rLenInfo.length;

  if (cursor >= signatureBytes.length || signatureBytes[cursor] !== 0x02) return null;
  const sLenInfo = readDerLen(signatureBytes, cursor + 1);
  if (!sLenInfo) return null;
  cursor = sLenInfo.next;
  if (cursor + sLenInfo.length !== signatureBytes.length) return null;
  const sRaw = signatureBytes.slice(cursor, cursor + sLenInfo.length);

  const rNoPrefix = padTo32BytesHex(bytesToHexNoPrefix(rRaw));
  const sNoPrefix = padTo32BytesHex(bytesToHexNoPrefix(sRaw));
  if (!rNoPrefix || !sNoPrefix) return null;

  return {
    r: `0x${rNoPrefix}`,
    s: `0x${sNoPrefix}`
  };
}

function recoverWithRS(message: string, r: string, s: string): string | null {
  const digest = hashMessage(message);
  for (const v of [27, 28] as const) {
    try {
      return getAddress(recoverAddress(digest, { r, s, v }));
    } catch {
      // try next recovery id
    }
  }
  return null;
}

function recoverAuthSigner(
  message: string,
  signatureInput: string
): { signer: string | null; format: string; details?: string } {
  const normalized = normalizeSignatureHex(signatureInput);

  try {
    return {
      signer: getAddress(verifyMessage(message, normalized)),
      format: "ethers_rsv_or_2098"
    };
  } catch {
    // fall through to extra formats
  }

  let bytes: Uint8Array;
  try {
    bytes = getBytes(normalized);
  } catch (error) {
    return {
      signer: null,
      format: "unknown",
      details: `invalid_hex_signature: ${(error as Error).message}`
    };
  }

  if (bytes.length === 64) {
    const r = `0x${bytesToHexNoPrefix(bytes.slice(0, 32))}`;
    const s = `0x${bytesToHexNoPrefix(bytes.slice(32, 64))}`;
    const signer = recoverWithRS(message, r, s);
    return {
      signer,
      format: "raw_r_plus_s_64",
      details: signer ? undefined : "cannot_recover_from_64_byte_r_plus_s"
    };
  }

  const der = parseDerEcdsa(bytes);
  if (der) {
    const signer = recoverWithRS(message, der.r, der.s);
    return {
      signer,
      format: "der_asn1",
      details: signer ? undefined : "cannot_recover_from_der_signature"
    };
  }

  return {
    signer: null,
    format: "unsupported",
    details: `unsupported_signature_length_${bytes.length}`
  };
}

function createAuthMessage(miner: string, nonce: string, issuedAtSec: number, expiresAtSec: number): string {
  const issuedAtIso = new Date(issuedAtSec * 1000).toISOString();
  const expiresAtIso = new Date(expiresAtSec * 1000).toISOString();
  return [
    "AGCOIN Coordinator Authentication",
    `Miner: ${miner}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAtIso}`,
    `Expires At: ${expiresAtIso}`
  ].join("\n");
}

function keyNonce(nonce: string): string {
  return `auth:nonce:${nonce}`;
}

function keyToken(token: string): string {
  return `auth:token:${token}`;
}

function keyChallenge(challengeId: string): string {
  return `challenge:${challengeId}`;
}

function keyMinerCredits(miner: string): string {
  return `credits:${miner.toLowerCase()}`;
}

function keyLock(kind: "challenge" | "submit", miner: string): string {
  return `lock:${kind}:${miner.toLowerCase()}`;
}

async function initStorage(): Promise<void> {
  if (redis) {
    redis.on("error", (error) => {
      console.error("redis error:", error);
    });
    await redis.connect();
    console.log("redis connected");
  }

  if (pgPool) {
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS coordinator_events (
        id BIGSERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        event_type TEXT NOT NULL,
        miner TEXT,
        epoch_id BIGINT,
        challenge_id TEXT,
        success BOOLEAN,
        status_code INTEGER,
        error_code TEXT,
        details JSONB
      );
    `);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_coordinator_events_created_at ON coordinator_events (created_at DESC);`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_coordinator_events_event_type ON coordinator_events (event_type);`);
    await pgPool.query(`CREATE INDEX IF NOT EXISTS idx_coordinator_events_miner_epoch ON coordinator_events (miner, epoch_id);`);
    console.log("postgres connected");
  }
}

async function logEvent(input: {
  eventType: string;
  miner?: string;
  epochId?: number;
  challengeId?: string;
  success?: boolean;
  statusCode?: number;
  errorCode?: string;
  details?: Record<string, unknown>;
}): Promise<void> {
  if (!pgPool) return;
  try {
    await pgPool.query(
      `INSERT INTO coordinator_events (event_type, miner, epoch_id, challenge_id, success, status_code, error_code, details)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        input.eventType,
        input.miner ?? null,
        input.epochId ?? null,
        input.challengeId ?? null,
        input.success ?? null,
        input.statusCode ?? null,
        input.errorCode ?? null,
        input.details ? JSON.stringify(input.details) : null
      ]
    );
  } catch (error) {
    console.error("failed to persist event:", error);
  }
}

function parseJsonRecord<T>(raw: string | null): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

async function setNonceRecord(nonce: string, value: NonceRecord): Promise<void> {
  authNonces.set(nonce, value);
  if (!redis) return;
  await redis.set(keyNonce(nonce), JSON.stringify(value), { EX: config.authNonceTtlSeconds });
}

async function getNonceRecord(nonce: string): Promise<NonceRecord | null> {
  const local = authNonces.get(nonce);
  if (local) return local;
  if (!redis) return null;
  const parsed = parseJsonRecord<NonceRecord>(await redis.get(keyNonce(nonce)));
  if (!parsed) return null;
  authNonces.set(nonce, parsed);
  return parsed;
}

async function deleteNonceRecord(nonce: string): Promise<void> {
  authNonces.delete(nonce);
  if (!redis) return;
  await redis.del(keyNonce(nonce));
}

async function setTokenRecord(token: string, value: TokenRecord): Promise<void> {
  authTokens.set(token, value);
  if (!redis) return;
  const ttl = Math.max(1, value.expiresAt - nowSeconds());
  await redis.set(keyToken(token), JSON.stringify(value), { EX: ttl });
}

async function getTokenRecord(token: string): Promise<TokenRecord | null> {
  const local = authTokens.get(token);
  if (local) return local;
  if (!redis) return null;
  const parsed = parseJsonRecord<TokenRecord>(await redis.get(keyToken(token)));
  if (!parsed) return null;
  authTokens.set(token, parsed);
  return parsed;
}

async function deleteTokenRecord(token: string): Promise<void> {
  authTokens.delete(token);
  if (!redis) return;
  await redis.del(keyToken(token));
}

async function setChallengeRecord(challenge: ChallengePayload): Promise<void> {
  challenges.set(challenge.challengeId, challenge);
  if (!redis) return;
  await redis.set(keyChallenge(challenge.challengeId), JSON.stringify(challenge), { EX: config.challengeTtlSeconds });
}

async function getChallengeRecord(challengeId: string): Promise<ChallengePayload | null> {
  const local = challenges.get(challengeId);
  if (local) return local;
  if (!redis) return null;
  const parsed = parseJsonRecord<ChallengePayload>(await redis.get(keyChallenge(challengeId)));
  if (!parsed) return null;
  challenges.set(challengeId, parsed);
  return parsed;
}

async function deleteChallengeRecord(challengeId: string): Promise<void> {
  challenges.delete(challengeId);
  if (!redis) return;
  await redis.del(keyChallenge(challengeId));
}

async function addCredits(miner: string, epochId: number, delta: number): Promise<void> {
  const creditKey = `${epochId}:${miner}`;
  creditsBook.set(creditKey, (creditsBook.get(creditKey) ?? 0) + delta);
  if (redis) {
    await redis.hIncrBy(keyMinerCredits(miner), String(epochId), delta);
    await redis.expire(keyMinerCredits(miner), 60 * 60 * 24 * 14);
  }
}

async function getMinerCredits(miner: string): Promise<Array<{ epochId: number; credits: number }>> {
  if (redis) {
    const values = await redis.hGetAll(keyMinerCredits(miner));
    return Object.entries(values)
      .map(([epochId, credits]) => ({ epochId: Number(epochId), credits: Number(credits) }))
      .filter((row) => Number.isFinite(row.epochId) && Number.isFinite(row.credits))
      .sort((a, b) => a.epochId - b.epochId);
  }

  const epochs = new Map<number, number>();
  for (const [key, value] of creditsBook.entries()) {
    const [epochPart, minerPart] = key.split(":");
    if (minerPart.toLowerCase() !== miner.toLowerCase()) continue;
    const epochId = Number(epochPart);
    epochs.set(epochId, (epochs.get(epochId) ?? 0) + value);
  }
  return Array.from(epochs.entries())
    .map(([epochId, credits]) => ({ epochId, credits }))
    .sort((a, b) => a.epochId - b.epochId);
}

async function acquireMinerLock(kind: "challenge" | "submit", miner: string, token: string): Promise<boolean> {
  const ttlMs = config.minerLockTtlSeconds * 1000;
  const lockKey = keyLock(kind, miner);
  if (redis) {
    const result = await redis.set(lockKey, token, { PX: ttlMs, NX: true });
    return result === "OK";
  }

  const existing = localLocks.get(lockKey);
  const now = Date.now();
  if (existing && existing.expiresAt > now) return false;
  localLocks.set(lockKey, { token, expiresAt: now + ttlMs });
  return true;
}

async function releaseMinerLock(kind: "challenge" | "submit", miner: string, token: string): Promise<void> {
  const lockKey = keyLock(kind, miner);
  if (redis) {
    // Only release lock if ownership token matches.
    const releaseScript = `
      if redis.call("GET", KEYS[1]) == ARGV[1] then
        return redis.call("DEL", KEYS[1])
      else
        return 0
      end
    `;
    await redis.eval(releaseScript, {
      keys: [lockKey],
      arguments: [token]
    });
    return;
  }

  const existing = localLocks.get(lockKey);
  if (existing?.token === token) {
    localLocks.delete(lockKey);
  }
}

async function getGenesisTimestamp(): Promise<bigint> {
  if (cachedGenesisTimestamp !== null) return cachedGenesisTimestamp;
  const value = (await mining.genesisTimestamp()) as bigint;
  cachedGenesisTimestamp = value;
  return value;
}

async function getTokenAddress(): Promise<string> {
  if (cachedTokenAddress) return getAddress(cachedTokenAddress);
  const value = (await mining.agcoinToken()) as string;
  cachedTokenAddress = value;
  return getAddress(value);
}

async function getEpochInfo() {
  const genesisTimestamp = await getGenesisTimestamp();
  const duration = BigInt(config.epochDurationSeconds);
  const now = BigInt(nowSeconds());
  const epochId = Number((now - genesisTimestamp) / duration);
  const prevEpochId = epochId > 0 ? epochId - 1 : null;
  const nextEpochStartTimestamp = Number(genesisTimestamp + BigInt(epochId + 1) * duration);

  return {
    epochId,
    prevEpochId,
    nextEpochStartTimestamp,
    epochDurationSeconds: config.epochDurationSeconds
  };
}

const COMPANIES = [
  "AstraForge",
  "Blue Meridian",
  "Cinder Labs",
  "Delta Loom",
  "Eon Harbor",
  "Flux Foundry",
  "Granite Cloud",
  "Helix Grove",
  "Ion Harbor",
  "Juniper Dynamics",
  "Kite Assembly",
  "Lumen Freight",
  "Mosaic Relay",
  "Nimbus Script",
  "Orbit Kiln",
  "Pillar Systems",
  "Quasar Mint",
  "Rivet Logic",
  "Signal Acre",
  "Tangent Works",
  "Umber Field",
  "Vector Pier",
  "Willow Compute",
  "Xeno Fabric",
  "Yardline Delta"
];

function toIndex(seed: bigint, divisor: bigint): number {
  return Number((seed / divisor) % BigInt(COMPANIES.length));
}

function deriveMetrics(company: string, seed: bigint) {
  const digest = BigInt(hashText(`${company}-${seed}`));
  const revenue = Number(digest % 900n) + 100;
  const staff = Number((digest / 997n) % 4500n) + 500;
  return { revenue, staff };
}

function distinctIndices(seed: bigint): [number, number, number] {
  let i1 = toIndex(seed, 1n);
  let i2 = toIndex(seed, 31n);
  let i3 = toIndex(seed, 101n);
  while (i2 === i1) i2 = (i2 + 1) % COMPANIES.length;
  while (i3 === i1 || i3 === i2) i3 = (i3 + 1) % COMPANIES.length;
  return [i1, i2, i3];
}

function buildChallenge(miner: string, nonce: string, epochId: number, creditsPerSolve: number): ChallengePayload {
  const seed = BigInt(keccak256(toUtf8Bytes(`${miner}:${nonce}:${epochId}`)));
  const [i1, i2, i3] = distinctIndices(seed);
  const picked = [COMPANIES[i1], COMPANIES[i2], COMPANIES[i3]];

  const metrics = new Map<string, { revenue: number; staff: number }>();
  for (const company of COMPANIES) {
    metrics.set(company, deriveMetrics(company, seed));
  }

  const candidates = picked.map((name) => ({ name, ...metrics.get(name)! }));
  const maxRevenue = [...candidates].sort((a, b) => b.revenue - a.revenue)[0].name;
  const minStaff = [...candidates].sort((a, b) => a.staff - b.staff)[0].name;
  const checksum = (maxRevenue.length + minStaff.length + epochId) % 97;
  const expectedArtifact = `${maxRevenue}|${minStaff}|${checksum}`;

  const docLines = COMPANIES.map((name) => {
    const row = metrics.get(name)!;
    return `${name} reported annual revenue ${row.revenue}M and staff size ${row.staff}.`;
  });

  const questions = [
    `Among ${picked.join(", ")}, which company has the highest revenue?`,
    `Among ${picked.join(", ")}, which company has the lowest staff size?`
  ];

  const constraints = [
    "Artifact must be one line in the format: <answer1>|<answer2>|<checksum>",
    `answer1 must equal the highest-revenue company among: ${picked.join(", ")}`,
    `answer2 must equal the lowest-staff company among: ${picked.join(", ")}`,
    "checksum must be (len(answer1) + len(answer2) + epochId) % 97"
  ];

  const challengeId = hashText(`${miner}:${nonce}:${epochId}:challenge`);

  return {
    challengeId,
    epochId,
    nonce,
    miner,
    doc: docLines.join("\n"),
    questions,
    constraints,
    companies: COMPANIES,
    expectedArtifact,
    creditsPerSolve,
    createdAt: nowSeconds()
  };
}

async function creditsForMiner(miner: string): Promise<number> {
  const tokenAddress = await getTokenAddress();
  const token = new Contract(tokenAddress, erc20Abi, provider);
  const [balance, tier1, tier2, tier3] = (await Promise.all([
    token.balanceOf(miner),
    mining.tier1Balance(),
    mining.tier2Balance(),
    mining.tier3Balance()
  ])) as [bigint, bigint, bigint, bigint];

  if (balance >= tier3) return 3;
  if (balance >= tier2) return 2;
  if (balance >= tier1) return 1;
  return 0;
}

function readBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  const [type, token] = authHeader.split(" ");
  if (type !== "Bearer" || !token) return null;
  return token;
}

async function authMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const token = readBearerToken(req);
    if (!token) {
      res.status(401).json({ error: "missing_bearer_token" });
      return;
    }

    const record = await getTokenRecord(token);
    if (!record || record.expiresAt < nowSeconds()) {
      if (record) await deleteTokenRecord(token);
      res.status(401).json({ error: "invalid_or_expired_token" });
      return;
    }

    res.locals.authMiner = record.miner;
    next();
  } catch (error) {
    next(error);
  }
}

const nonceBodySchema = z.object({ miner: z.string() });
const verifyBodySchema = z.object({ miner: z.string(), message: z.string(), signature: z.string() });
const submitSchema = z.object({
  miner: z.string(),
  challengeId: z.string(),
  artifact: z.string().min(1),
  nonce: z.string().min(1).max(64)
});

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  const start = Date.now();
  const key = `${req.method} ${req.path}`;
  metricsState.requestsTotal += 1;

  res.on("finish", () => {
    const duration = Date.now() - start;
    const entry = metricsState.endpoint.get(key) ?? { count: 0, errors: 0, totalDurationMs: 0 };
    entry.count += 1;
    entry.totalDurationMs += duration;
    if (res.statusCode >= 400) {
      entry.errors += 1;
      metricsState.requestErrors += 1;
    }
    metricsState.endpoint.set(key, entry);
  });

  next();
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "agcoin-coordinator",
    redis: redis ? (redis.isOpen ? "up" : "down") : "disabled",
    postgres: pgPool ? "enabled" : "disabled"
  });
});

app.get("/v1/token", async (_req, res, next) => {
  try {
    const token = await getTokenAddress();
    res.json({ token });
  } catch (error) {
    next(error);
  }
});

app.get("/v1/epoch", async (_req, res, next) => {
  try {
    const data = await getEpochInfo();
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.post("/v1/auth/nonce", async (req, res, next) => {
  try {
    const parsed = nonceBodySchema.parse(req.body);
    const miner = getAddress(parsed.miner);
    const nonce = randomHex(16);
    const issuedAt = nowSeconds();
    const expiresAt = issuedAt + config.authNonceTtlSeconds;
    const message = createAuthMessage(miner, nonce, issuedAt, expiresAt);

    await setNonceRecord(nonce, {
      miner,
      message,
      expiresAt
    });

    await logEvent({
      eventType: "auth_nonce_issued",
      miner,
      success: true
    });

    res.json({ miner, nonce, message, expiresAt: new Date(expiresAt * 1000).toISOString() });
  } catch (error) {
    next(error);
  }
});

app.post("/v1/auth/verify", async (req, res, next) => {
  try {
    const parsed = verifyBodySchema.parse(req.body);
    const miner = getAddress(parsed.miner);

    const nonce = parseNonceFromMessage(parsed.message);
    if (!nonce) {
      res.status(400).json({ error: "nonce_not_found_in_message" });
      return;
    }

    const nonceRecord = await getNonceRecord(nonce);
    if (!nonceRecord || nonceRecord.expiresAt < nowSeconds()) {
      if (nonceRecord) await deleteNonceRecord(nonce);
      await logEvent({
        eventType: "auth_verify_failed",
        miner,
        success: false,
        statusCode: 401,
        errorCode: "nonce_missing_or_expired"
      });
      res.status(401).json({ error: "nonce_missing_or_expired" });
      return;
    }

    if (nonceRecord.miner !== miner || nonceRecord.message !== parsed.message) {
      await logEvent({
        eventType: "auth_verify_failed",
        miner,
        success: false,
        statusCode: 401,
        errorCode: "nonce_context_mismatch"
      });
      res.status(401).json({ error: "nonce_context_mismatch" });
      return;
    }

    const recoveredResult = recoverAuthSigner(parsed.message, parsed.signature);
    if (!recoveredResult.signer) {
      await logEvent({
        eventType: "auth_verify_failed",
        miner,
        success: false,
        statusCode: 401,
        errorCode: "signature_parse_failed",
        details: { formatTried: recoveredResult.format }
      });
      res.status(401).json({
        error: "invalid_signature",
        reason: "signature_parse_failed",
        formatTried: recoveredResult.format,
        details: recoveredResult.details
      });
      return;
    }

    if (recoveredResult.signer !== miner) {
      await logEvent({
        eventType: "auth_verify_failed",
        miner,
        success: false,
        statusCode: 401,
        errorCode: "recovered_mismatch",
        details: { recoveredSigner: recoveredResult.signer, formatUsed: recoveredResult.format }
      });
      res.status(401).json({
        error: "invalid_signature",
        reason: "recovered_mismatch",
        formatUsed: recoveredResult.format,
        expectedMiner: miner,
        recoveredSigner: recoveredResult.signer
      });
      return;
    }

    await deleteNonceRecord(nonce);

    const token = randomHex(32);
    const expiresAt = nowSeconds() + config.authTokenTtlSeconds;
    await setTokenRecord(token, { miner, expiresAt });

    await logEvent({
      eventType: "auth_verify_success",
      miner,
      success: true
    });

    res.json({ token, expiresAt: new Date(expiresAt * 1000).toISOString() });
  } catch (error) {
    next(error);
  }
});

app.get("/v1/challenge", authMiddleware, async (req, res, next) => {
  try {
    const miner = getAddress(String(req.query.miner ?? ""));
    const nonce = String(req.query.nonce ?? "");
    const authMiner = res.locals.authMiner as string;

    if (!nonce || nonce.length > 64) {
      res.status(400).json({ error: "invalid_nonce" });
      return;
    }

    if (authMiner !== miner) {
      res.status(403).json({ error: "token_miner_mismatch" });
      return;
    }

    const lockToken = randomHex(12);
    const acquired = await acquireMinerLock("challenge", miner, lockToken);
    if (!acquired) {
      res.status(429).json({ error: "challenge_lock_busy", message: "another challenge request is in flight for this miner" });
      return;
    }

    try {
      const { epochId } = await getEpochInfo();

      const epochCommit = (await mining.epochCommit(BigInt(epochId))) as string;
      if (epochCommit === "0x0000000000000000000000000000000000000000000000000000000000000000") {
        await logEvent({
          eventType: "challenge_denied",
          miner,
          epochId,
          success: false,
          statusCode: 409,
          errorCode: "missing_epoch_commit"
        });
        res.status(409).json({ error: "missing_epoch_commit", message: "epoch commit is not set on-chain yet" });
        return;
      }

      const creditsPerSolve = await creditsForMiner(miner);
      if (creditsPerSolve === 0) {
        await logEvent({
          eventType: "challenge_denied",
          miner,
          epochId,
          success: false,
          statusCode: 403,
          errorCode: "insufficient_balance_for_tier"
        });
        res.status(403).json({ error: "insufficient_balance_for_tier" });
        return;
      }

      const challenge = buildChallenge(miner, nonce, epochId, creditsPerSolve);
      await setChallengeRecord(challenge);

      await logEvent({
        eventType: "challenge_issued",
        miner,
        epochId,
        challengeId: challenge.challengeId,
        success: true,
        statusCode: 200
      });

      res.json({
        challengeId: challenge.challengeId,
        epochId: challenge.epochId,
        nonce: challenge.nonce,
        doc: challenge.doc,
        questions: challenge.questions,
        constraints: challenge.constraints,
        companies: challenge.companies,
        creditsPerSolve: challenge.creditsPerSolve,
        solveInstructions:
          "Your response must be exactly one line — the artifact string and nothing else. No reasoning, no JSON, no preamble."
      });
    } finally {
      await releaseMinerLock("challenge", miner, lockToken);
    }
  } catch (error) {
    next(error);
  }
});

app.post("/v1/submit", authMiddleware, async (req, res, next) => {
  try {
    const parsed = submitSchema.parse(req.body);
    const miner = getAddress(parsed.miner);
    const authMiner = res.locals.authMiner as string;
    if (authMiner !== miner) {
      res.status(403).json({ error: "token_miner_mismatch" });
      return;
    }

    const lockToken = randomHex(12);
    const acquired = await acquireMinerLock("submit", miner, lockToken);
    if (!acquired) {
      res.status(429).json({ error: "submit_lock_busy", message: "another submit is in flight for this miner" });
      return;
    }

    try {
      const challenge = await getChallengeRecord(parsed.challengeId);
      if (!challenge || challenge.miner !== miner || challenge.nonce !== parsed.nonce) {
        await logEvent({
          eventType: "submit_failed",
          miner,
          challengeId: parsed.challengeId,
          success: false,
          statusCode: 404,
          errorCode: "challenge_not_found_or_nonce_mismatch"
        });
        res.status(404).json({ error: "challenge_not_found_or_nonce_mismatch" });
        return;
      }

      if (parsed.artifact.trim() !== challenge.expectedArtifact) {
        await logEvent({
          eventType: "submit_failed",
          miner,
          epochId: challenge.epochId,
          challengeId: challenge.challengeId,
          success: false,
          statusCode: 200,
          errorCode: "failed_constraints",
          details: { failedConstraintIndices: [0] }
        });
        res.json({ pass: false, failedConstraintIndices: [0] });
        return;
      }

      const [epochData, solveIndex, prevReceiptHash] = await Promise.all([
        getEpochInfo(),
        mining.nextIndex(miner) as Promise<bigint>,
        mining.lastReceiptHash(miner) as Promise<string>
      ]);

      if (epochData.epochId !== challenge.epochId) {
        await logEvent({
          eventType: "submit_failed",
          miner,
          epochId: challenge.epochId,
          challengeId: challenge.challengeId,
          success: false,
          statusCode: 404,
          errorCode: "stale_challenge_epoch"
        });
        res.status(404).json({ error: "stale_challenge_epoch" });
        return;
      }

      const challengeId = challenge.challengeId;
      const commit = hashText(parsed.artifact);
      const docHash = hashText(challenge.doc);
      const questionsHash = hashText(JSON.stringify(challenge.questions));
      const constraintsHash = hashText(JSON.stringify(challenge.constraints));
      const answersHash = hashText(parsed.artifact);

      const worldSeedHash = keccak256(toUtf8Bytes(`${miner}:${challengeId}:${parsed.nonce}:worldseed`));
      const worldSeed = BigInt(worldSeedHash) & ((1n << 128n) - 1n);

      const receiptValue = {
        miner,
        epochId: BigInt(challenge.epochId),
        solveIndex,
        prevReceiptHash,
        challengeId,
        commit,
        docHash,
        questionsHash,
        constraintsHash,
        answersHash,
        worldSeed,
        rulesVersion: BigInt(config.rulesVersion)
      };

      const domain = {
        name: config.eip712Name,
        version: config.eip712Version,
        chainId: config.chainId,
        verifyingContract: getAddress(config.miningContractAddress)
      };

      const types = {
        Receipt: [
          { name: "miner", type: "address" },
          { name: "epochId", type: "uint64" },
          { name: "solveIndex", type: "uint64" },
          { name: "prevReceiptHash", type: "bytes32" },
          { name: "challengeId", type: "bytes32" },
          { name: "commit", type: "bytes32" },
          { name: "docHash", type: "bytes32" },
          { name: "questionsHash", type: "bytes32" },
          { name: "constraintsHash", type: "bytes32" },
          { name: "answersHash", type: "bytes32" },
          { name: "worldSeed", type: "uint128" },
          { name: "rulesVersion", type: "uint32" }
        ]
      } as const;

      const signature = await coordinatorSigner.signTypedData(domain, types, receiptValue);

      const txData = miningInterface.encodeFunctionData("submitReceipt", [
        receiptValue.epochId,
        receiptValue.solveIndex,
        receiptValue.prevReceiptHash,
        receiptValue.challengeId,
        receiptValue.commit,
        receiptValue.docHash,
        receiptValue.questionsHash,
        receiptValue.constraintsHash,
        receiptValue.answersHash,
        receiptValue.worldSeed,
        receiptValue.rulesVersion,
        signature
      ]);

      await addCredits(miner, challenge.epochId, challenge.creditsPerSolve);
      await deleteChallengeRecord(challenge.challengeId);

      await logEvent({
        eventType: "submit_pass",
        miner,
        epochId: challenge.epochId,
        challengeId: challenge.challengeId,
        success: true,
        statusCode: 200,
        details: { creditsPerSolve: challenge.creditsPerSolve }
      });

      res.json({
        pass: true,
        receipt: {
          miner,
          epochId: challenge.epochId,
          solveIndex: solveIndex.toString(),
          prevReceiptHash,
          challengeId,
          commit,
          docHash,
          questionsHash,
          constraintsHash,
          answersHash,
          worldSeed: worldSeed.toString(),
          rulesVersion: config.rulesVersion
        },
        signature,
        transaction: {
          to: getAddress(config.miningContractAddress),
          chainId: config.chainId,
          value: "0",
          data: txData
        },
        creditsPerSolve: challenge.creditsPerSolve
      });
    } finally {
      await releaseMinerLock("submit", miner, lockToken);
    }
  } catch (error) {
    next(error);
  }
});

app.get("/v1/claim-calldata", (req, res, next) => {
  try {
    const raw = String(req.query.epochs ?? "").trim();
    if (!raw) {
      res.status(400).json({ error: "missing_epochs_query" });
      return;
    }

    const epochs = raw.split(",").map((value) => {
      const trimmed = value.trim();
      if (!/^\d+$/.test(trimmed)) throw new Error(`Invalid epoch id: ${trimmed}`);
      return BigInt(trimmed);
    });

    const txData = miningInterface.encodeFunctionData("claim", [epochs]);
    res.json({
      transaction: {
        to: getAddress(config.miningContractAddress),
        chainId: config.chainId,
        value: "0",
        data: txData
      }
    });
  } catch (error) {
    next(error);
  }
});

function checkAdminAccess(req: Request): boolean {
  if (!config.adminApiKey) return false;
  const provided = req.header("x-admin-key");
  return provided === config.adminApiKey;
}

app.get("/v1/credits", async (req, res) => {
  try {
    const minerRaw = String(req.query.miner ?? "").trim();
    if (!minerRaw) {
      res.status(400).json({ error: "miner_required" });
      return;
    }
    const miner = getAddress(minerRaw);
    const epochs = await getMinerCredits(miner);
    res.json({ miner, epochs });
  } catch (error) {
    res.status(400).json({ error: "invalid_miner_address", message: (error as Error).message });
  }
});

app.get("/v1/admin/metrics", async (req, res, next) => {
  try {
    if (!checkAdminAccess(req)) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }

    const endpoints = Array.from(metricsState.endpoint.entries())
      .map(([endpoint, value]) => ({
        endpoint,
        count: value.count,
        errors: value.errors,
        avgDurationMs: value.count > 0 ? Number((value.totalDurationMs / value.count).toFixed(2)) : 0
      }))
      .sort((a, b) => b.count - a.count);

    let recentEvents: Array<Record<string, unknown>> = [];
    let eventsLastHour = 0;
    let submitPassLastHour = 0;
    let submitFailLastHour = 0;

    if (pgPool) {
      const [eventsCount, submitPassCount, submitFailCount, latest] = await Promise.all([
        pgPool.query(`SELECT COUNT(*)::int AS count FROM coordinator_events WHERE created_at > NOW() - INTERVAL '1 hour'`),
        pgPool.query(`SELECT COUNT(*)::int AS count FROM coordinator_events WHERE created_at > NOW() - INTERVAL '1 hour' AND event_type = 'submit_pass'`),
        pgPool.query(`SELECT COUNT(*)::int AS count FROM coordinator_events WHERE created_at > NOW() - INTERVAL '1 hour' AND event_type = 'submit_failed'`),
        pgPool.query(`
          SELECT created_at, event_type, miner, epoch_id, challenge_id, success, status_code, error_code
          FROM coordinator_events
          ORDER BY created_at DESC
          LIMIT 20
        `)
      ]);
      eventsLastHour = eventsCount.rows[0]?.count ?? 0;
      submitPassLastHour = submitPassCount.rows[0]?.count ?? 0;
      submitFailLastHour = submitFailCount.rows[0]?.count ?? 0;
      recentEvents = latest.rows as Array<Record<string, unknown>>;
    }

    res.json({
      service: "agcoin-coordinator",
      processStartedAt: metricsState.processStartedAt,
      uptimeSeconds: Math.floor(process.uptime()),
      requestsTotal: metricsState.requestsTotal,
      requestErrors: metricsState.requestErrors,
      endpointStats: endpoints,
      redisConnected: redis ? redis.isOpen : false,
      postgresEnabled: Boolean(pgPool),
      postgres: {
        eventsLastHour,
        submitPassLastHour,
        submitFailLastHour
      },
      recentEvents
    });
  } catch (error) {
    next(error);
  }
});

app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof z.ZodError) {
    res.status(400).json({ error: "invalid_request", details: err.flatten() });
    return;
  }

  if (err instanceof Error) {
    void logEvent({
      eventType: "request_error",
      success: false,
      statusCode: 500,
      errorCode: "internal_error",
      details: {
        path: req.path,
        method: req.method,
        message: err.message
      }
    });
    res.status(500).json({ error: "internal_error", message: err.message });
    return;
  }

  res.status(500).json({ error: "internal_error" });
});

let server: ReturnType<typeof app.listen> | null = null;

async function startServer(): Promise<void> {
  await initStorage();
  server = app.listen(config.port, () => {
    console.log(`agcoin-coordinator listening on :${config.port}`);
    console.log(`mining contract: ${getAddress(config.miningContractAddress)} | chainId: ${config.chainId}`);
    console.log(`coordinator signer: ${coordinatorSigner.address}`);
    console.log(`redis: ${redis ? "enabled" : "disabled"} | postgres: ${pgPool ? "enabled" : "disabled"}`);
  });
}

let shuttingDown = false;

function gracefulShutdown(signal: NodeJS.Signals) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`received ${signal}, shutting down gracefully...`);

  const finish = async () => {
    try {
      if (redis?.isOpen) await redis.quit();
      if (pgPool) await pgPool.end();
    } catch (error) {
      console.error("error during storage shutdown:", error);
    }
    process.exit(0);
  };

  if (!server) {
    void finish();
    return;
  }

  server.close((error) => {
    if (error) {
      console.error("error during server close:", error);
      process.exit(1);
      return;
    }
    void finish();
  });

  // Safety timeout to avoid hanging indefinitely.
  setTimeout(() => {
    console.error("forced shutdown after timeout");
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

void startServer().catch((error) => {
  console.error("failed to start server:", error);
  process.exit(1);
});
