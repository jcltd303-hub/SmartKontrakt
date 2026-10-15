import { getSql } from "@/lib/db";
import type { Finding, Report, Severity } from "./types";
import type { ProxyAnalysis } from "./proxy-resolver";
import type { CallProbeResult } from "./simulator";
import type { AiSecurityReview } from "./ai-review.server";

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

interface RagDbRow {
  id: string;
  scan_id: string | null;
  category: string;
  title: string;
  content: string;
  severity: string | null;
  swc: string | null;
  detector: string | null;
  contract_name: string | null;
  target_address: string | null;
  chain_id: string | null;
  keywords: string;
  vector_data: string | null;
  metadata_json: string;
  created_at: string;
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
 * Tokenize string into meaningful search terms, removing common stop words
 */
function tokenize(text: string): string[] {
  const clean = text.toLowerCase().replace(/[^a-z0-9_#$]/g, " ");
  const stopWords = new Set(["the", "and", "or", "to", "in", "a", "of", "for", "with", "on", "at", "by", "from", "is", "this", "that", "it"]);
  return clean
    .split(/\s+/)
    .filter((w) => w.length > 2 && !stopWords.has(w));
}

/**
 * Compute semantic match relevance score between a query and a RAG chunk (0 - 100)
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
 * Ingest an audit report and its comprehensive metadata into RAG knowledgebase chunks
 */
export async function indexReportToRag(params: {
  scanId: string;
  report: Report;
  rawBody?: string;
  targetAddress?: string | null;
  chainId?: string | null;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[] | null;
  aiReview?: AiSecurityReview | null;
}): Promise<{ chunksCreated: number }> {
  const { scanId, report, targetAddress, chainId, proxyInfo, probes, aiReview } = params;
  const sql = await getSql();
  const contractName = report.inventory.contractNames[0] ?? report.label;
  const chunksToInsert: Omit<RagDbRow, "created_at">[] = [];

  // 1. Chunks for each finding
  for (let idx = 0; idx < report.findings.length; idx++) {
    const f: Finding = report.findings[idx];
    const chunkId = `rag-${scanId}-finding-${idx}-${Math.random().toString(36).slice(2, 6)}`;
    const title = `[${f.severity.toUpperCase()}] ${f.title} (${f.detector})`;
    const content = `${f.title}\nSeverity: ${f.severity.toUpperCase()} | SWC: ${f.swc ?? "N/A"} | Detector: ${f.detector}\n\nSummary:\n${f.summary}\n\nWalkthrough & Root Cause:\n${f.walkthrough}\n${f.snippet ? `\nCode Snippet:\n${f.snippet}` : ""}`;
    const keywords = [
      f.detector,
      f.swc ?? "",
      f.severity,
      contractName,
      ...tokenize(f.title),
      ...tokenize(f.summary).slice(0, 5),
    ].filter(Boolean).join(", ");

    chunksToInsert.push({
      id: chunkId,
      scan_id: scanId,
      category: "vulnerability",
      title,
      content,
      severity: f.severity,
      swc: f.swc ?? null,
      detector: f.detector,
      contract_name: contractName,
      target_address: targetAddress ?? null,
      chain_id: chainId ?? "ethereum",
      keywords,
      vector_data: null,
      metadata_json: JSON.stringify({
        locationFn: f.locationFn,
        locationLine: f.locationLine,
        snippet: f.snippet,
        exploitSolidity: f.exploitSolidity,
        remediationSolidity: f.remediationSolidity,
      }),
    });

    // If finding has specific remediation code, create a dedicated remediation chunk
    if (f.remediationSolidity && f.remediationSolidity.trim().length > 10) {
      const remId = `rag-${scanId}-rem-${idx}-${Math.random().toString(36).slice(2, 6)}`;
      chunksToInsert.push({
        id: remId,
        scan_id: scanId,
        category: "remediation",
        title: `Remediation Pattern: Fix for ${f.title}`,
        content: `Remediation strategy for ${f.title} (${f.detector} / ${f.swc ?? "SWC"}):\n\nSolidity Fix Pattern:\n${f.remediationSolidity}\n\nContext:\n${f.walkthrough}`,
        severity: f.severity,
        swc: f.swc ?? null,
        detector: f.detector,
        contract_name: contractName,
        target_address: targetAddress ?? null,
        chain_id: chainId ?? "ethereum",
        keywords: ["remediation", "patch", "fix", f.detector, f.swc ?? "", contractName].filter(Boolean).join(", "),
        vector_data: null,
        metadata_json: JSON.stringify({
          remediationSolidity: f.remediationSolidity,
          locationFn: f.locationFn,
        }),
      });
    }
  }

  // 2. Threat Model & AI Narrative Chunk
  if (aiReview?.threatModelReport || report.aiNarrative) {
    const narrativeText = aiReview?.threatModelReport || report.aiNarrative || "";
    const tmId = `rag-${scanId}-threatmodel`;
    chunksToInsert.push({
      id: tmId,
      scan_id: scanId,
      category: "threat_model",
      title: `Executive Threat Model: ${contractName}`,
      content: `Threat Model Analysis for ${contractName}:\n\n${narrativeText}`,
      severity: report.riskScore > 60 ? "critical" : report.riskScore > 30 ? "high" : "medium",
      swc: null,
      detector: "ai-threat-model",
      contract_name: contractName,
      target_address: targetAddress ?? null,
      chain_id: chainId ?? "ethereum",
      keywords: ["threat model", "attack surface", "risk narrative", contractName].join(", "),
      vector_data: null,
      metadata_json: JSON.stringify({
        riskScore: report.riskScore,
        aiAttackVectors: aiReview?.attackVectors ?? [],
      }),
    });
  }

  // 3. Executable Foundry Test PoC Chunk
  if (aiReview?.foundryTestCode && aiReview.foundryTestCode.trim().length > 20) {
    const pocId = `rag-${scanId}-foundry-poc`;
    chunksToInsert.push({
      id: pocId,
      scan_id: scanId,
      category: "foundry_poc",
      title: `Foundry Exploit PoC Suite: ${contractName}`,
      content: `Executable Foundry test suite (Exploit.t.sol) demonstrating vulnerability exploitation on ${contractName}:\n\n${aiReview.foundryTestCode}`,
      severity: "high",
      swc: null,
      detector: "foundry-poc",
      contract_name: contractName,
      target_address: targetAddress ?? null,
      chain_id: chainId ?? "ethereum",
      keywords: ["foundry", "exploit.t.sol", "poc", "test", contractName].join(", "),
      vector_data: null,
      metadata_json: JSON.stringify({
        foundryTestCode: aiReview.foundryTestCode,
      }),
    });
  }

  // 4. Contract Architecture & Interface Profile Chunk
  const profileId = `rag-${scanId}-profile`;
  const probeSummary = probes && probes.length > 0
    ? probes.map((p) => `${p.name} (${p.selector}): ${p.success ? (p.decodedString || p.decodedNumber || p.decodedAddress || "Returned") : "Reverted"}`).join("; ")
    : "No RPC probes recorded";
  const proxyNote = proxyInfo?.isProxy
    ? `Upgrade Pattern: ${proxyInfo.proxyType} Proxy (Impl: ${proxyInfo.implementationAddress}, Admin: ${proxyInfo.adminAddress ?? "None"})`
    : "Non-proxy direct implementation";

  chunksToInsert.push({
    id: profileId,
    scan_id: scanId,
    category: "contract_profile",
    title: `Contract Architecture & On-Chain Profile: ${contractName}`,
    content: `Architecture Dossier for ${contractName} (${targetAddress ?? "Unspecified Address"} on ${chainId ?? "ethereum"}):\n\n${proxyNote}\n\nCompiler / Pragma: ${report.inventory.compiler ?? report.inventory.pragma ?? "Unknown"}\nFunctions: ${report.inventory.functions.length} detected\nState Variables: ${report.inventory.stateVars.length} detected\nOn-Chain Probes:\n${probeSummary}\n\nInventory Notes:\n${report.inventory.notes.join("\n")}`,
    severity: "architecture",
    swc: null,
    detector: "architecture-profile",
    contract_name: contractName,
    target_address: targetAddress ?? null,
    chain_id: chainId ?? "ethereum",
    keywords: ["architecture", "profile", "probes", proxyInfo?.proxyType ?? "", contractName].filter(Boolean).join(", "),
    vector_data: null,
    metadata_json: JSON.stringify({
      proxyInfo: proxyInfo ?? null,
      probesCount: probes?.length ?? 0,
      functionsCount: report.inventory.functions.length,
    }),
  });

  // Batch insert into database
  for (const c of chunksToInsert) {
    try {
      await sql`
        insert into rag_knowledge_chunks (
          id, scan_id, category, title, content, severity, swc, detector,
          contract_name, target_address, chain_id, keywords, vector_data, metadata_json
        ) values (
          ${c.id}, ${c.scan_id}, ${c.category}, ${c.title}, ${c.content}, ${c.severity},
          ${c.swc}, ${c.detector}, ${c.contract_name}, ${c.target_address}, ${c.chain_id},
          ${c.keywords}, ${c.vector_data}, ${c.metadata_json}
        )
        on conflict (id) do update set
          title = excluded.title,
          content = excluded.content,
          keywords = excluded.keywords,
          metadata_json = excluded.metadata_json
      `;
    } catch (err) {
      console.warn("[kiln-rag] Chunk insert warning for id:", c.id, err);
    }
  }

  // Mark scan as indexed in contract_scans
  try {
    await sql`update contract_scans set is_rag_indexed = true where id = ${scanId}`;
  } catch {
    // ignore
  }

  return { chunksCreated: chunksToInsert.length };
}

/**
 * Optimized bulk ingestion of multiple audit reports into RAG knowledgebase chunks
 */
export async function indexBatchReportsToRag(items: {
  scanId: string;
  report: Report;
  rawBody?: string;
  targetAddress?: string | null;
  chainId?: string | null;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[] | null;
  aiReview?: AiSecurityReview | null;
}[]): Promise<{ totalChunksCreated: number }> {
  if (!items.length) return { totalChunksCreated: 0 };
  let totalChunks = 0;

  for (const item of items) {
    try {
      const res = await indexReportToRag(item);
      totalChunks += res.chunksCreated;
    } catch (err) {
      console.warn("[kiln-rag] Batch chunk index item error:", item.scanId, err);
    }
  }

  return { totalChunksCreated: totalChunks };
}

/**
 * Ensure canonical knowledge advisories exist in the local database
 */
export async function seedCanonicalRagKnowledge(): Promise<void> {
  const sql = await getSql();
  for (const item of CANONICAL_KNOWLEDGE_ADVISORIES) {
    try {
      await sql`
        insert into rag_knowledge_chunks (
          id, scan_id, category, title, content, severity, swc, detector,
          contract_name, target_address, chain_id, keywords, vector_data, metadata_json
        ) values (
          ${item.id}, ${null}, ${item.category}, ${item.title}, ${item.content},
          ${item.severity}, ${item.swc}, ${item.detector}, ${item.contractName},
          ${item.targetAddress}, ${item.chainId}, ${item.keywords.join(", ")}, ${null},
          ${JSON.stringify(item.metadata)}
        )
        on conflict (id) do nothing
      `;
    } catch {
      // Table might not exist or already seeded
    }
  }
}

/**
 * Search the RAG knowledgebase with semantic keyword & token matching
 */
export async function queryRagKnowledgebase(params: {
  query: string;
  category?: string;
  minSeverity?: string;
  limit?: number;
}): Promise<RagChunk[]> {
  const sql = await getSql();
  await seedCanonicalRagKnowledge();

  try {
    let rows: RagDbRow[] = [];
    if (params.category && params.category !== "all") {
      rows = await sql<RagDbRow>`
        select id, scan_id, category, title, content, severity, swc, detector,
               contract_name, target_address, chain_id, keywords, vector_data, metadata_json,
               created_at::text as created_at
        from rag_knowledge_chunks
        where category = ${params.category}
        order by created_at desc
        limit 150
      `;
    } else {
      rows = await sql<RagDbRow>`
        select id, scan_id, category, title, content, severity, swc, detector,
               contract_name, target_address, chain_id, keywords, vector_data, metadata_json,
               created_at::text as created_at
        from rag_knowledge_chunks
        order by created_at desc
        limit 150
      `;
    }

    const chunks = rows.map(rowToChunk);
    const query = params.query.trim();

    if (!query) {
      return chunks.slice(0, params.limit ?? 25).map((c) => ({
        ...c,
        relevanceScore: 100,
        highlightSnippet: c.content.slice(0, 160) + "...",
      }));
    }

    // Score and rank all chunks
    const scored = chunks
      .map((c) => {
        const { score, highlight } = scoreChunk(query, c);
        return {
          ...c,
          relevanceScore: score,
          highlightSnippet: highlight,
        };
      })
      .filter((c) => (c.relevanceScore ?? 0) > 15)
      .sort((a, b) => (b.relevanceScore ?? 0) - (a.relevanceScore ?? 0));

    return scored.slice(0, params.limit ?? 25);
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
  await seedCanonicalRagKnowledge();
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
