// The staked/reward token symbol is always ZEN — hardcoded rather than read
// from the contract, so the UX label is stable regardless of which token
// address a given deployment points at.

const SYMBOL = "ZEN";

export function getTokenSymbol(): string {
  return SYMBOL;
}

export function fetchTokenSymbol(): Promise<string> {
  return Promise.resolve(SYMBOL);
}

export function useTokenSymbol(): string {
  return SYMBOL;
}
