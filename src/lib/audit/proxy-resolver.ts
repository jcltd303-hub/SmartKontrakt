import { SUPPORTED_CHAINS } from "./address-fetcher.ts";
import { rpcPool } from "./rpc-endpoints.ts";
import { rpcLimiter, withRetry } from "./rate-limit.ts";

export type ProxyAnalysis = {
  isProxy: boolean;
  proxyType: "EIP-1967" | "ERC-1822" | "Beacon" | "Custom" | "None";
  implementationAddress: string | null;
  adminAddress: string | null;
  beaconAddress: string | null;
  isImplementationInitialized?: boolean;
  notes: string[];
};

// Known proxy storage slots
const EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const ERC1822_SLOT = "0xc5f2ac40cbb8469b643d2854e04024395f564476ec644e4024395f564476ec64";

/**
 * Extracts a 20-byte address from a 32-byte EVM storage word
 */
function cleanStorageAddress(hexWord: string): string | null {
  if (!hexWord || hexWord === "0x" || hexWord === "0x0" || /^0x0+$/.test(hexWord)) {
    return null;
  }
  const stripped = hexWord.replace(/^0x/, "").padStart(64, "0");
  const addressHex = "0x" + stripped.slice(24);
  if (/^0x0{40}$/.test(addressHex)) return null;
  return addressHex.toLowerCase();
}

/**
 * Read storage slot using eth_getStorageAt via public EVM JSON-RPC
 */
async function getStorageAtRpc(address: string, slot: string, rpcUrls: string[]): Promise<string | null> {
  for (const rpcUrl of rpcUrls) {
    try {
      const res = await withRetry(async () => {
        await rpcLimiter.acquire();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);
        try {
          return await fetch(rpcUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              method: "eth_getStorageAt",
              params: [address, slot, "latest"],
              id: 1,
            }),
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timer);
        }
      }, { retries: 1, baseDelayMs: 1500 });
      if (!res.ok) {
        rpcPool.note(rpcUrl, { ok: false, status: res.status });
        continue;
      }
      rpcPool.note(rpcUrl, { ok: true });

      const data = (await res.json()) as { result?: string };
      if (data.result && typeof data.result === "string") {
        return data.result;
      }
    } catch {
      // try next RPC
    }
  }
  return null;
}

/**
 * Automatically inspects an on-chain address for Upgradeable Proxy patterns
 */
export async function detectProxyArchitecture(address: string, chainId = "ethereum"): Promise<ProxyAnalysis> {
  const chain = SUPPORTED_CHAINS.find((c) => c.id === chainId) ?? SUPPORTED_CHAINS[0]!;
  const notes: string[] = [];

  // Query standard slots in parallel
  const [implSlot, adminSlot, beaconSlot, erc1822Slot] = await Promise.all([
    getStorageAtRpc(address, EIP1967_IMPLEMENTATION_SLOT, chain.rpcUrls),
    getStorageAtRpc(address, EIP1967_ADMIN_SLOT, chain.rpcUrls),
    getStorageAtRpc(address, EIP1967_BEACON_SLOT, chain.rpcUrls),
    getStorageAtRpc(address, ERC1822_SLOT, chain.rpcUrls),
  ]);

  const implementation = cleanStorageAddress(implSlot || "");
  const admin = cleanStorageAddress(adminSlot || "");
  const beacon = cleanStorageAddress(beaconSlot || "");
  const erc1822Impl = cleanStorageAddress(erc1822Slot || "");

  if (implementation) {
    notes.push(`Detected standard EIP-1967 Transparent/UUPS Proxy pointing to ${implementation}.`);
    if (admin) notes.push(`Proxy Admin controller slot resolved: ${admin}`);
    return {
      isProxy: true,
      proxyType: "EIP-1967",
      implementationAddress: implementation,
      adminAddress: admin,
      beaconAddress: null,
      notes,
    };
  }

  if (beacon) {
    notes.push(`Detected EIP-1967 Beacon Proxy pointing to Beacon contract ${beacon}.`);
    return {
      isProxy: true,
      proxyType: "Beacon",
      implementationAddress: null,
      adminAddress: admin,
      beaconAddress: beacon,
      notes,
    };
  }

  if (erc1822Impl) {
    notes.push(`Detected Universal Upgradeable Proxy Standard (ERC-1822) pointing to ${erc1822Impl}.`);
    return {
      isProxy: true,
      proxyType: "ERC-1822",
      implementationAddress: erc1822Impl,
      adminAddress: admin,
      beaconAddress: null,
      notes,
    };
  }

  return {
    isProxy: false,
    proxyType: "None",
    implementationAddress: null,
    adminAddress: null,
    beaconAddress: null,
    notes: ["No standard upgradeable proxy slots resolved on this contract."],
  };
}
