import cors from "cors";
import dotenv from "dotenv";
import express, { type Request, type Response, type NextFunction } from "express";
import {
  Contract,
  Interface,
  JsonRpcProvider,
  Wallet,
  getAddress,
  keccak256,
  randomBytes,
  solidityPacked,
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
  eip712Name: process.env.EIP712_NAME ?? "BotcoinMining",
  eip712Version: process.env.EIP712_VERSION ?? "1",
  rulesVersion: Number(process.env.RULES_VERSION ?? 1),
  agcoinTokenAddress: process.env.AGCOIN_TOKEN_ADDRESS,
  genesisTimestampEnv: process.env.GENESIS_TIMESTAMP
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
  "function botcoinToken() view returns (address)",
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

async function getGenesisTimestamp(): Promise<bigint> {
  if (cachedGenesisTimestamp !== null) return cachedGenesisTimestamp;
  const value = (await mining.genesisTimestamp()) as bigint;
  cachedGenesisTimestamp = value;
  return value;
}

async function getTokenAddress(): Promise<string> {
  if (cachedTokenAddress) return getAddress(cachedTokenAddress);
  const value = (await mining.botcoinToken()) as string;
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

function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = readBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "missing_bearer_token" });
    return;
  }

  const record = authTokens.get(token);
  if (!record || record.expiresAt < nowSeconds()) {
    if (record) authTokens.delete(token);
    res.status(401).json({ error: "invalid_or_expired_token" });
    return;
  }

  res.locals.authMiner = record.miner;
  next();
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

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "agcoin-coordinator" });
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

app.post("/v1/auth/nonce", (req, res, next) => {
  try {
    const parsed = nonceBodySchema.parse(req.body);
    const miner = getAddress(parsed.miner);
    const nonce = randomHex(16);
    const issuedAt = nowSeconds();
    const expiresAt = issuedAt + config.authNonceTtlSeconds;
    const message = createAuthMessage(miner, nonce, issuedAt, expiresAt);

    authNonces.set(nonce, {
      miner,
      message,
      expiresAt
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

    const nonceRecord = authNonces.get(nonce);
    if (!nonceRecord || nonceRecord.expiresAt < nowSeconds()) {
      if (nonceRecord) authNonces.delete(nonce);
      res.status(401).json({ error: "nonce_missing_or_expired" });
      return;
    }

    if (nonceRecord.miner !== miner || nonceRecord.message !== parsed.message) {
      res.status(401).json({ error: "nonce_context_mismatch" });
      return;
    }

    const recovered = getAddress(verifyMessage(parsed.message, parsed.signature));
    if (recovered !== miner) {
      res.status(401).json({ error: "invalid_signature" });
      return;
    }

    authNonces.delete(nonce);

    const token = randomHex(32);
    const expiresAt = nowSeconds() + config.authTokenTtlSeconds;
    authTokens.set(token, { miner, expiresAt });

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

    const { epochId } = await getEpochInfo();
    const creditsPerSolve = await creditsForMiner(miner);
    if (creditsPerSolve === 0) {
      res.status(403).json({ error: "insufficient_balance_for_tier" });
      return;
    }

    const challenge = buildChallenge(miner, nonce, epochId, creditsPerSolve);
    challenges.set(challenge.challengeId, challenge);

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

    const challenge = challenges.get(parsed.challengeId);
    if (!challenge || challenge.miner !== miner || challenge.nonce !== parsed.nonce) {
      res.status(404).json({ error: "challenge_not_found_or_nonce_mismatch" });
      return;
    }

    if (parsed.artifact.trim() !== challenge.expectedArtifact) {
      res.json({ pass: false, failedConstraintIndices: [0] });
      return;
    }

    const [epochData, solveIndex, prevReceiptHash] = await Promise.all([
      getEpochInfo(),
      mining.nextIndex(miner) as Promise<bigint>,
      mining.lastReceiptHash(miner) as Promise<string>
    ]);

    if (epochData.epochId !== challenge.epochId) {
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

    const creditKey = `${challenge.epochId}:${miner}`;
    creditsBook.set(creditKey, (creditsBook.get(creditKey) ?? 0) + challenge.creditsPerSolve);
    challenges.delete(challenge.challengeId);

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

app.get("/v1/credits", (req, res) => {
  try {
    const minerRaw = String(req.query.miner ?? "");
    const miner = minerRaw ? getAddress(minerRaw) : "";

    const epochs = new Map<number, number>();
    for (const [key, value] of creditsBook.entries()) {
      const [epochPart, minerPart] = key.split(":");
      if (!miner || minerPart.toLowerCase() !== miner.toLowerCase()) continue;
      const epochId = Number(epochPart);
      epochs.set(epochId, (epochs.get(epochId) ?? 0) + value);
    }

    res.json({
      miner: miner || null,
      epochs: Array.from(epochs.entries())
        .map(([epochId, credits]) => ({ epochId, credits }))
        .sort((a, b) => a.epochId - b.epochId)
    });
  } catch (error) {
    res.status(400).json({ error: "invalid_miner_address", message: (error as Error).message });
  }
});

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof z.ZodError) {
    res.status(400).json({ error: "invalid_request", details: err.flatten() });
    return;
  }

  if (err instanceof Error) {
    res.status(500).json({ error: "internal_error", message: err.message });
    return;
  }

  res.status(500).json({ error: "internal_error" });
});

app.listen(config.port, () => {
  console.log(`agcoin-coordinator listening on :${config.port}`);
  console.log(`mining contract: ${getAddress(config.miningContractAddress)} | chainId: ${config.chainId}`);
  console.log(`coordinator signer: ${coordinatorSigner.address}`);
});
