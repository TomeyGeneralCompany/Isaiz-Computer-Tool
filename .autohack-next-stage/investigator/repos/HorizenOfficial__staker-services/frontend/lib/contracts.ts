import {
  BrowserProvider,
  Contract,
  JsonRpcProvider,
  JsonRpcSigner,
  Network,
} from "ethers";
import { CONFIG } from "./config";
import { ZEN_STAKER_ABI, ZEN_TOKEN_ABI } from "./abi";

// Singleton read provider + contracts. The chain id is fixed, so we pin a static
// network: this skips ethers' per-provider eth_chainId auto-detection, and
// reusing one instance across all polling hooks avoids re-instantiating (and
// re-detecting) the provider on every read.
let readProvider: JsonRpcProvider | null = null;
let readContracts: { staker: Contract; token: Contract } | null = null;

// Read-only provider for view calls (no wallet required).
export function getReadProvider(): JsonRpcProvider {
  if (!readProvider) {
    const network = Network.from(CONFIG.chainId);
    readProvider = new JsonRpcProvider(CONFIG.rpc, network, {
      staticNetwork: network,
    });
  }
  return readProvider;
}

export function getReadContracts() {
  if (!readContracts) {
    const provider = getReadProvider();
    readContracts = {
      staker: new Contract(CONFIG.contractStaker, ZEN_STAKER_ABI, provider),
      token: new Contract(CONFIG.contractToken, ZEN_TOKEN_ABI, provider),
    };
  }
  return readContracts;
}

declare global {
  interface Window {
    ethereum?: import("ethers").Eip1193Provider;
  }
}

// Connect MetaMask (or any EIP-1193 provider) and return a signer.
export async function connectWallet(): Promise<JsonRpcSigner> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No EIP-1193 wallet found. Please install MetaMask.");
  }
  const browserProvider = new BrowserProvider(window.ethereum);
  await browserProvider.send("eth_requestAccounts", []);
  return browserProvider.getSigner();
}

export function getSignedContracts(signer: JsonRpcSigner) {
  return {
    staker: new Contract(CONFIG.contractStaker, ZEN_STAKER_ABI, signer),
    token: new Contract(CONFIG.contractToken, ZEN_TOKEN_ABI, signer),
  };
}
