import type { RagDbRow } from "./rag-chunks";
import { tokenize } from "./tokenize";
import { getSql } from "@/lib/db";
import type { Severity } from "./types";
import { SEVERITY_ORDER } from "./severity.ts";

export interface RagChunk {
  id: string;
  scanId: string | null;
  category: "vulnerability" | "threat_model" | "remediation" | "contract_profile" | "foundry_poc";
  title: string;
  content: string;
  severity: Severity | "architecture" | "general";
  swc: string | null;
  detector: string | null;
  contractName: string | null;
  targetAddress: string | null;
  chainId: string | null;
  keywords: string[];
  metadata: {
    snippet?: string;
    locationLine?: number | null;
    locationFn?: string | null;
    exploitSolidity?: string;
    remediationSolidity?: string;
    foundryTestCode?: string;
    sourceOrigin?: string;
    verifiedHash?: string;
    probesCount?: number;
    proxyType?: string;
    riskScore?: number;
    aiAttackVectors?: string[];
    [key: string]: string | number | boolean | null | undefined | string[];
  };
  createdAt: string;
  relevanceScore?: number;
  highlightSnippet?: string;
}


function rowToChunk(row: RagDbRow): RagChunk {
  let parsedMeta = {};
  try {
    parsedMeta = JSON.parse(row.metadata_json);
  } catch {
    parsedMeta = {};
  }

  return {
    id: row.id,
    scanId: row.scan_id,
    category: row.category as RagChunk["category"],
    title: row.title,
    content: row.content,
    severity: (row.severity ?? "info") as RagChunk["severity"],
    swc: row.swc,
    detector: row.detector,
    contractName: row.contract_name,
    targetAddress: row.target_address,
    chainId: row.chain_id,
    keywords: row.keywords ? row.keywords.split(",").map((k) => k.trim()) : [],
    metadata: parsedMeta,
    createdAt: row.created_at,
  };
}

/** Pre-seeded canonical smart contract vulnerabilities for immediate knowledgebase utility */
export const CANONICAL_KNOWLEDGE_ADVISORIES: Omit<RagChunk, "createdAt">[] = [
  {
    id: "kb-reentrancy-dao",
    scanId: null,
    category: "vulnerability",
    title: "Classic Reentrancy with External Ether Transfer (The DAO Pattern)",
    content: `Reentrancy occurs when an external contract call transfers control flow to an untrusted recipient before state updates (balances, deposits, withdrawals) are finalized. The recipient fallback or receive function re-enters the vulnerable method repeatedly, draining protocol funds before the original execution checks and updates the storage balance.
Remediation mandates strict Checks-Effects-Interactions pattern: deduct balance in local storage prior to initiating transfer, or apply OpenZeppelin ReentrancyGuard nonReentrant modifier.`,
    severity: "critical",
    swc: "SWC-107",
    detector: "reentrancy-eth",
    contractName: "The DAO Reference",
    targetAddress: "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
    chainId: "ethereum",
    keywords: ["reentrancy", "withdraw", "call.value", "msg.sender.call", "checks-effects-interactions", "nonReentrant", "SWC-107"],
    metadata: {
      locationFn: "withdraw()",
      remediationSolidity: `function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount; // Effect before interaction
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "ETH transfer failed");
}`,
      exploitSolidity: `contract AttackDAO {
    IDao public target;
    constructor(address _target) { target = IDao(_target); }
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}`,
    },
  },
  {
    id: "kb-readonly-reentrancy-curve",
    scanId: null,
    category: "vulnerability",
    title: "Read-Only Reentrancy in AMM LP Token Oracle Calculations",
    content: `Read-only reentrancy does not modify the target pool state during reentrancy, but exploits transient imbalanced state (e.g. Virtual Price or Spot Price calculations during remove_liquidity) while another protocol queries the pool as a price oracle. Lending markets computing collateral value during the reentrancy window will read inflated or deflated collateral valuations, allowing attackers to borrow unbacked funds.
Remediation requires oracles to invoke reentrancy-guarded view functions or utilize TWAP / Chainlink price feeds rather than instantaneous reserve ratios.`,
    severity: "high",
    swc: "SWC-107",
    detector: "reentrancy-readonly",
    contractName: "Curve / Balancer LP Oracle Reference",
    targetAddress: "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7",
    chainId: "ethereum",
    keywords: ["read-only reentrancy", "oracle", "get_virtual_price", "remove_liquidity", "flash loan", "collateral valuation"],
    metadata: {
      locationFn: "get_virtual_price()",
      remediationSolidity: `// In consumer lending protocol:
// Verify pool is not currently in a reentrancy state:
function getSafePrice(address pool) public view returns (uint256) {
    // Check pool reentrancy lock or utilize Chainlink verified TWAP
    return ICurvePool(pool).get_virtual_price();
}`,
    },
  },
  {
    id: "kb-unchecked-erc20-usdt",
    scanId: null,
    category: "vulnerability",
    title: "Unchecked ERC-20 Return Values & Non-Standard Tokens (USDT / BNB)",
    content: `Standard ERC-20 interface requires transfer() and transferFrom() to return a boolean true on success. However, popular tokens like USDT (Tether on Ethereum) and BNB do not return a boolean value (void return). Directly calling token.transfer() in Solidity expecting a bool causes an EVM decode revert. Furthermore, tokens like ZRX return false instead of reverting on insufficient allowance.
Remediation: Always use OpenZeppelin SafeERC20 with safeTransfer() and safeTransferFrom() to handle both non-reverting false returns and missing boolean return values safely.`,
    severity: "high",
    swc: "SWC-104",
    detector: "unchecked-transfer",
    contractName: "SafeERC20 Compliance Pattern",
    targetAddress: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    chainId: "ethereum",
    keywords: ["unchecked transfer", "SafeERC20", "USDT", "transferFrom", "boolean return", "SWC-104"],
    metadata: {
      locationFn: "transferFrom()",
      remediationSolidity: `using SafeERC20 for IERC20;

function depositTokens(IERC20 token, uint256 amount) external {
    token.safeTransferFrom(msg.sender, address(this), amount);
    userBalances[msg.sender] += amount;
}`,
    },
  },
  {
    id: "kb-proxy-eip1967-storage-collision",
    scanId: null,
    category: "vulnerability",
    title: "EIP-1967 Upgradeable Proxy Storage Collision & Uninitialized Logic",
    content: `Upgradeable proxies (UUPS or Transparent) delegate all state execution to an implementation contract while holding state in proxy storage. Two major security risks exist:
1. Storage collisions: if implementation contract modifies variable layout order or introduces variables in non-append slots, storage variables overwrite each other.
2. Uninitialized logic contract: if the implementation contract constructor does not disable initializers (_disableInitializers()), an attacker can call initialize() on the implementation directly, claim ownership, and execute selfdestruct or delegatecall.
Remediation: Adopt OpenZeppelin ERC1967Proxy with Storage Gap buffers (__gap) and lock implementation constructors with _disableInitializers().`,
    severity: "critical",
    swc: "SWC-112",
    detector: "uninitialized-implementation",
    contractName: "EIP-1967 Proxy Standard",
    targetAddress: null,
    chainId: "ethereum",
    keywords: ["proxy", "upgradeable", "EIP-1967", "storage collision", "uninitialized", "UUPS", "initialize"],
    metadata: {
      locationFn: "initialize()",
      remediationSolidity: `/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers(); // Locks logic contract from direct takeover
}

function initialize(address admin) public initializer {
    __Ownable_init(admin);
    __UUPSUpgradeable_init();
}`,
    },
  },
  {
    id: "kb-delegatecall-storage-collision-atomic-drain",
    scanId: null,
    category: "vulnerability",
    title: "SWC-112: Delegatecall Storage Collision & Atomic Multi-Step Drain",
    content: `Unlike CALL which executes in the target context, DELEGATECALL executes foreign code in the context of the calling contract (preserving storage, balance, and msg.sender).
When a delegatecall target is caller-supplied or unconstrained:
1. Storage Layout Collision: An attacker provides a malicious contract matching Slot 0 layout (owner/admin), overwriting contract ownership.
2. Atomic Extraction: Within the same atomic transaction, the attacker immediately leverages newly acquired ownership to sweep tokens and native balance (seizeAndDrain) before external monitors can react.
3. Remediation: Enforce EIP-1967 isolated pseudo-random slots (_IMPLEMENTATION_SLOT, _ADMIN_SLOT), maintain a strict implementation whitelist, and prohibit passing unvalidated callee addresses to delegatecall.`,
    severity: "critical",
    swc: "SWC-112",
    detector: "delegatecall",
    contractName: "Storage Collision & Delegator Standard",
    targetAddress: null,
    chainId: "ethereum",
    keywords: ["delegatecall", "storage collision", "SWC-112", "slot 0", "seizeAndDrain", "EIP-1967", "whitelist"],
    metadata: {
      locationFn: "delegateTo()",
      remediationSolidity: `// EIP-1967 Storage Slot Isolation + Strict Implementation Whitelist
bytes32 private constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
mapping(address => bool) public allowedImplementations;

function upgradeToAndCall(address newImpl, bytes calldata data) external onlyOwner {
    require(allowedImplementations[newImpl], "Unauthorized implementation");
    assembly {
        sstore(_IMPLEMENTATION_SLOT, newImpl)
    }
    (bool ok, ) = newImpl.delegatecall(data);
    require(ok, "Delegatecall failed");
}`,
    },
  },
  {
    id: "kb-erc4626-first-depositor-inflation",
    scanId: null,
    category: "vulnerability",
    title: "ERC-4626 First Depositor Share Inflation & Rounding Exploit",
    content: `ERC-4626 tokenized vaults determine share minting via the ratio (assets * totalShares) / totalAssets. An attacker can deposit 1 wei of assets to receive 1 wei of shares, then directly transfer a large amount of assets (e.g. 10,000 USDC) directly to the vault contract address without minting shares.
Subsequent victims depositing amounts under 10,000 USDC round down to 0 shares due to integer division truncation, completely losing their deposit to the first depositor.
Remediation: Enforce virtual offset shares (OpenZeppelin ERC4626 virtual decimals) or burn dead initial shares (e.g., 1000 shares to address(0)).`,
    severity: "high",
    swc: "SWC-101",
    detector: "erc4626-inflation",
    contractName: "ERC-4626 Vault Architecture",
    targetAddress: null,
    chainId: "ethereum",
    keywords: ["ERC-4626", "inflation attack", "first depositor", "virtual shares", "rounding", "vault"],
    metadata: {
      locationFn: "deposit()",
      remediationSolidity: `// Use OpenZeppelin 4.9+ virtual shares implementation:
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
    return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
}`,
    },
  },
];

/**
 * Compute a lexical match relevance score between a query and a chunk (0 - 100).
 * Used only by the in-memory fallback when the database is unreachable; the
 * primary path ranks with Postgres full-text search.
 */
function scoreChunk(query: string, chunk: RagChunk): { score: number; highlight: string } {
  const queryTokens = tokenize(query);
  if (queryTokens.length === 0) return { score: 50, highlight: chunk.content.slice(0, 180) + "..." };

  const contentLower = chunk.content.toLowerCase();
  const titleLower = chunk.title.toLowerCase();
  const detectorLower = (chunk.detector ?? "").toLowerCase();
  const swcLower = (chunk.swc ?? "").toLowerCase();
  const contractLower = (chunk.contractName ?? "").toLowerCase();

  let matchedTokens = 0;
  let score = 0;
  let firstMatchIndex = -1;

  for (const token of queryTokens) {
    let tokenHit = false;
    // Title match has highest weight
    if (titleLower.includes(token)) {
      score += 35;
      tokenHit = true;
    }
    // SWC or detector exact match
    if (detectorLower.includes(token) || swcLower.includes(token)) {
      score += 40;
      tokenHit = true;
    }
    // Keywords match
    if (chunk.keywords.some((k) => k.toLowerCase().includes(token))) {
      score += 25;
      tokenHit = true;
    }
    // Contract name match
    if (contractLower.includes(token)) {
      score += 20;
      tokenHit = true;
    }
    // Content body match
    const idx = contentLower.indexOf(token);
    if (idx !== -1) {
      score += 15;
      tokenHit = true;
      if (firstMatchIndex === -1 || idx < firstMatchIndex) {
        firstMatchIndex = idx;
      }
    }
    if (tokenHit) matchedTokens += 1;
  }

  // Completeness ratio
  const tokenCoverage = matchedTokens / queryTokens.length;
  score = score * tokenCoverage;

  // Severity bonus for high-impact knowledge
  if (chunk.severity === "critical") score += 10;
  else if (chunk.severity === "high") score += 5;

  const normalizedScore = Math.min(100, Math.round(score));

  // Extract snippet surrounding first match
  let highlight = "";
  if (firstMatchIndex !== -1) {
    const start = Math.max(0, firstMatchIndex - 50);
    const end = Math.min(chunk.content.length, firstMatchIndex + 140);
    highlight = (start > 0 ? "..." : "") + chunk.content.slice(start, end).trim() + (end < chunk.content.length ? "..." : "");
  } else {
    highlight = chunk.content.slice(0, 160) + "...";
  }

  return { score: normalizedScore, highlight };
}

/**
 * Canonical knowledge advisories.
 *
 * RAG eliminated 2026-10-21 (storage): seeding writes are OFF — this is an
 * intentional no-op. Reads use the in-memory CANONICAL_KNOWLEDGE_ADVISORIES
 * list as their fallback instead of rows in the dropped table.
 */
export async function seedCanonicalRagKnowledge(): Promise<void> {
  // RAG eliminated 2026-10-21 (storage): no seeding writes.
  return;
}

/**
 * Seed the canonical advisories at most once per process. Safe to call on every
 * read: after the first success it is a no-op, and a failure is retried next
 * call. (Previously every query re-ran the six upserts.)
 */
let canonicalSeeded = false;
async function ensureCanonicalRagSeeded(): Promise<void> {
  if (canonicalSeeded) return;
  try {
    await seedCanonicalRagKnowledge();
    canonicalSeeded = true;
  } catch {
    // leave the flag false so the next call retries
  }
}

/** A short snippet around the first matching token, for the result list. */
function highlightFor(query: string, content: string): string {
  const fallback = content.slice(0, 160) + (content.length > 160 ? "..." : "");
  const lower = content.toLowerCase();
  let idx = -1;
  for (const token of tokenize(query)) {
    const at = lower.indexOf(token);
    if (at !== -1 && (idx === -1 || at < idx)) idx = at;
  }
  if (idx === -1) idx = lower.indexOf(query.trim().toLowerCase());
  if (idx === -1) return fallback;
  const start = Math.max(0, idx - 50);
  const end = Math.min(content.length, idx + 140);
  return (start > 0 ? "..." : "") + content.slice(start, end).trim() + (end < content.length ? "..." : "");
}


/** Severities at or above `min`; null when no filter should apply. */
function severitiesAtLeast(min: string | undefined): string[] | null {
  if (!min) return null;
  const idx = SEVERITY_ORDER.indexOf(min as (typeof SEVERITY_ORDER)[number]);
  if (idx === -1) return null;
  return [...SEVERITY_ORDER.slice(idx)];
}

type RagRowWithRank = RagDbRow & { rank?: number };

/**
 * Search the knowledge base.
 *
 * With a query, Postgres full-text search (`websearch_to_tsquery` + `ts_rank_cd`,
 * backed by the GIN index from migration 0009) ranks every chunk — there is no
 * "newest 150 rows" window, so older chunks stay reachable. When a query matches
 * nothing through FTS (a rare token, a stopword-only query), a substring `ilike`
 * pass catches it. With no query, the newest chunks are returned. Category and
 * minimum-severity filters are applied in SQL.
 */
export async function queryRagKnowledgebase(params: {
  query: string;
  category?: string;
  minSeverity?: string;
  limit?: number;
}): Promise<RagChunk[]> {
  const sql = await getSql();
  await ensureCanonicalRagSeeded();

  const limit = Math.min(Math.max(Math.floor(params.limit ?? 25), 1), 100);
  const category = params.category && params.category !== "all" ? params.category : null;
  const severities = severitiesAtLeast(params.minSeverity);
  const query = params.query.trim();

  try {
    if (!query) {
      const rows = await sql<RagDbRow>`
        select id, scan_id, category, title, content, severity, swc, detector,
               contract_name, target_address, chain_id, keywords, vector_data, metadata_json,
               created_at::text as created_at
        from rag_knowledge_chunks
        where (${category}::text is null or category = ${category})
          and (${severities}::text[] is null or severity = any(${severities}))
        order by created_at desc
        limit ${limit}
      `;
      return rows.map(rowToChunk).map((c) => ({
        ...c,
        relevanceScore: 100,
        highlightSnippet: c.content.slice(0, 160) + "...",
      }));
    }

    const ranked = await sql<RagRowWithRank>`
      select id, scan_id, category, title, content, severity, swc, detector,
             contract_name, target_address, chain_id, keywords, vector_data, metadata_json,
             created_at::text as created_at,
             ts_rank_cd(search_vector, websearch_to_tsquery('english', ${query})) as rank
      from rag_knowledge_chunks
      where search_vector @@ websearch_to_tsquery('english', ${query})
        and (${category}::text is null or category = ${category})
        and (${severities}::text[] is null or severity = any(${severities}))
      order by rank desc, created_at desc
      limit ${limit}
    `;
    if (ranked.length) {
      return ranked.map((r) => {
        const chunk = rowToChunk(r);
        return {
          ...chunk,
          relevanceScore: Math.min(100, Math.max(1, Math.round((r.rank ?? 0) * 100))),
          highlightSnippet: highlightFor(query, chunk.content),
        };
      });
    }

    // FTS found nothing (uncommon token / stopwords only): fall back to a
    // literal substring match so a plain-word search still returns results.
    const like = `%${query.replace(/[%_\\]/g, "")}%`;
    const fallback = await sql<RagDbRow>`
      select id, scan_id, category, title, content, severity, swc, detector,
             contract_name, target_address, chain_id, keywords, vector_data, metadata_json,
             created_at::text as created_at
      from rag_knowledge_chunks
      where (title ilike ${like} or content ilike ${like} or keywords ilike ${like})
        and (${category}::text is null or category = ${category})
        and (${severities}::text[] is null or severity = any(${severities}))
      order by created_at desc
      limit ${limit}
    `;
    return fallback.map((r) => {
      const chunk = rowToChunk(r);
      return { ...chunk, relevanceScore: 60, highlightSnippet: highlightFor(query, chunk.content) };
    });
  } catch (err) {
    console.warn("[kiln-rag] Query failed, returning in-memory canonical seed:", err);
    // Fallback to in-memory canonical advisories
    return CANONICAL_KNOWLEDGE_ADVISORIES.map((c) => {
      const { score, highlight } = scoreChunk(params.query, { ...c, createdAt: new Date().toISOString() });
      return {
        ...c,
        createdAt: new Date().toISOString(),
        relevanceScore: score,
        highlightSnippet: highlight,
      };
    })
      .filter((c) => (c.relevanceScore ?? 0) > 15)
      .sort((a, b) => (b.relevanceScore ?? 0) - (a.relevanceScore ?? 0));
  }
}

/**
 * List all knowledgebase chunks with metadata for inspection
 */
export async function listRagKnowledgeChunks(limit: number = 80): Promise<RagChunk[]> {
  const sql = await getSql();
  await ensureCanonicalRagSeeded();
  try {
    const rows = await sql<RagDbRow>`
      select id, scan_id, category, title, content, severity, swc, detector,
             contract_name, target_address, chain_id, keywords, vector_data, metadata_json,
             created_at::text as created_at
      from rag_knowledge_chunks
      order by created_at desc
      limit ${limit}
    `;
    return rows.map(rowToChunk);
  } catch (err) {
    console.warn("[kiln-rag] listRagKnowledgeChunks failed:", err);
    return CANONICAL_KNOWLEDGE_ADVISORIES.map((c) => ({ ...c, createdAt: new Date().toISOString() }));
  }
}

/**
 * Delete a specific RAG knowledge chunk
 */
export async function deleteRagChunk(chunkId: string): Promise<boolean> {
  const sql = await getSql();
  await sql`delete from rag_knowledge_chunks where id = ${chunkId}`;
  return true;
}
