"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { BrowserProvider, JsonRpcSigner } from "ethers";
import { connectWallet, getReadContracts } from "./contracts";
import { CONFIG } from "./config";
import { fetchTokenSymbol } from "./tokenSymbol";

interface WalletState {
  address: string | null;
  chainId: number | null;
  signer: JsonRpcSigner | null;
  connecting: boolean;
  error: string | null;
  isCorrectChain: boolean;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  switchChain: () => Promise<void>;
  // Register the network / the staked token with the wallet (EIP-3085 /
  // EIP-747). Neither requires a connected account.
  addNetwork: () => Promise<void>;
  addToken: () => Promise<void>;
}

function chainParams() {
  return {
    chainId: "0x" + CONFIG.chainId.toString(16),
    chainName: CONFIG.chainName,
    nativeCurrency: { name: CONFIG.nativeCurrency, symbol: CONFIG.nativeCurrency, decimals: 18 },
    rpcUrls: [CONFIG.rpc],
    ...(CONFIG.explorerUrl ? { blockExplorerUrls: [CONFIG.explorerUrl] } : {}),
  };
}

// Mobile browsers can't run extensions, so the MetaMask app never injects
// window.ethereum there — the dApp must be opened inside MetaMask's own
// in-app browser instead. The universal link below does exactly that.
function metamaskDeepLink() {
  const { host, pathname, search } = window.location;
  return `https://metamask.app.link/dapp/${host}${pathname}${search}`;
}

function isMobileBrowser() {
  return /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
}

// A deliberate "Cancel" in the wallet popup is not a failure — don't surface
// it as an error. EIP-1193 signals it as code 4001; ethers wraps it as
// ACTION_REJECTED.
function isUserRejection(e: unknown): boolean {
  const err = e as { code?: number | string; message?: string };
  return (
    err?.code === 4001 ||
    err?.code === "ACTION_REJECTED" ||
    (typeof err?.message === "string" && err.message.toLowerCase().includes("user rejected"))
  );
}

type WalletSnapshot =
  | { connected: false }
  | { connected: true; address: string; chainId: number; signer: JsonRpcSigner };

const WalletContext = createContext<WalletState | null>(null);

export function WalletProvider({ children }: { children: React.ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);
  const [signer, setSigner] = useState<JsonRpcSigner | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<WalletSnapshot | null> => {
    if (typeof window === "undefined" || !window.ethereum) return null;
    const provider = new BrowserProvider(window.ethereum);
    const accounts = await provider.send("eth_accounts", []);
    if (accounts.length === 0) return { connected: false };
    const net = await provider.getNetwork();
    const s = await provider.getSigner();
    return {
      connected: true,
      address: await s.getAddress(),
      chainId: Number(net.chainId),
      signer: s,
    };
  }, []);

  const switchChain = useCallback(async () => {
    if (!window.ethereum) return;
    const hexId = "0x" + CONFIG.chainId.toString(16);
    setError(null);
    try {
      await window.ethereum.request?.({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: hexId }],
      });
    } catch (e) {
      // 4902: the wallet doesn't know this chain — add it (which also makes it
      // current). A user rejection is silent; other codes surface as an error.
      const code = (e as { code?: number })?.code;
      if (code === 4902) {
        try {
          await window.ethereum.request?.({
            method: "wallet_addEthereumChain",
            params: [chainParams()],
          });
        } catch (addErr) {
          if (!isUserRejection(addErr)) {
            setError(addErr instanceof Error ? addErr.message : "Failed to add network.");
          }
        }
        return;
      }
      if (!isUserRejection(e)) {
        setError(e instanceof Error ? e.message : "Failed to switch network.");
      }
    }
  }, []);

  const addNetwork = useCallback(async () => {
    if (!window.ethereum) return;
    setError(null);
    try {
      await window.ethereum.request?.({
        method: "wallet_addEthereumChain",
        params: [chainParams()],
      });
    } catch (e) {
      if (!isUserRejection(e)) {
        setError(e instanceof Error ? e.message : "Failed to add network.");
      }
    }
  }, []);

  const addToken = useCallback(async () => {
    if (!window.ethereum) return;
    setError(null);
    try {
      // wallet_watchAsset registers the token against whatever chain is
      // currently active in the wallet — since CONFIG.contractToken is only
      // valid on CONFIG.chainId, switch (or add) that chain first or the
      // token gets added under the wrong network.
      await switchChain();
      // MetaMask rejects the request if symbol/decimals don't match the
      // contract's own values exactly (e.g. testnet token is "tZEN", not the
      // "ZEN" label used elsewhere in the UI) — read them on-chain instead of
      // assuming.
      const { token } = getReadContracts();
      const [onChainSymbol, onChainDecimals] = await Promise.all([
        token.symbol() as Promise<string>,
        token.decimals() as Promise<bigint>,
      ]);
      await window.ethereum.request?.({
        method: "wallet_watchAsset",
        params: {
          type: "ERC20",
          options: { address: CONFIG.contractToken, symbol: onChainSymbol, decimals: Number(onChainDecimals) },
        },
      });
    } catch (e) {
      if (!isUserRejection(e)) {
        setError(e instanceof Error ? e.message : "Failed to add token.");
      }
    }
  }, [switchChain]);

  const connect = useCallback(async () => {
    // No injected provider on a mobile browser → hand off to the MetaMask
    // in-app browser via its universal link instead of failing.
    if (!window.ethereum && isMobileBrowser()) {
      window.location.href = metamaskDeepLink();
      return;
    }
    setConnecting(true);
    setError(null);
    try {
      const s = await connectWallet();
      const net = await s.provider.getNetwork();
      setSigner(s);
      setAddress(await s.getAddress());
      setChainId(Number(net.chainId));
      // Connected on the wrong network → prompt the wallet to switch right away
      // instead of leaving the user on a passive "wrong network" state.
      if (Number(net.chainId) !== CONFIG.chainId) {
        await switchChain();
      }
    } catch (e) {
      if (!isUserRejection(e)) {
        setError(e instanceof Error ? e.message : "Failed to connect.");
      }
    } finally {
      setConnecting(false);
    }
  }, [switchChain]);

  const disconnect = useCallback(async () => {
    // Revoke the eth_accounts permission so the eager reconnect on next load
    // won't pick the account back up. Not all wallets support this — fall back
    // to just clearing local state.
    try {
      await window.ethereum?.request?.({
        method: "wallet_revokePermissions",
        params: [{ eth_accounts: {} }],
      });
    } catch {
      /* unsupported — local state clear below is the fallback */
    }
    setAddress(null);
    setSigner(null);
  }, []);

  // Single startup RPC for the token symbol; cached for the process lifetime.
  useEffect(() => {
    fetchTokenSymbol();
  }, []);

  useEffect(() => {
    const apply = (snap: WalletSnapshot | null) => {
      if (!snap) return;
      if (!snap.connected) {
        setAddress(null);
        setSigner(null);
        return;
      }
      setChainId(snap.chainId);
      setAddress(snap.address);
      setSigner(snap.signer);
    };
    refresh().then(apply);
    const eth = window.ethereum as unknown as {
      on?: (e: string, cb: (...a: unknown[]) => void) => void;
      removeListener?: (e: string, cb: (...a: unknown[]) => void) => void;
    };
    if (!eth?.on) return;
    const onAccounts = () => refresh().then(apply);
    const onChain = () => refresh().then(apply);
    eth.on("accountsChanged", onAccounts);
    eth.on("chainChanged", onChain);
    return () => {
      eth.removeListener?.("accountsChanged", onAccounts);
      eth.removeListener?.("chainChanged", onChain);
    };
  }, [refresh]);

  const value = useMemo<WalletState>(
    () => ({
      address,
      chainId,
      signer,
      connecting,
      error,
      isCorrectChain: chainId === CONFIG.chainId,
      connect,
      disconnect,
      switchChain,
      addNetwork,
      addToken,
    }),
    [address, chainId, signer, connecting, error, connect, disconnect, switchChain, addNetwork, addToken]
  );

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function useWallet(): WalletState {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWallet must be used within WalletProvider");
  return ctx;
}
