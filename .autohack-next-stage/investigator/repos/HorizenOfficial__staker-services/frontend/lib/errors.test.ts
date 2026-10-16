import { describe, expect, it } from "vitest";
import { Interface } from "ethers";
import { decodeStakeError } from "./errors";
import { ZEN_STAKER_ABI } from "./abi";

const iface = new Interface(ZEN_STAKER_ABI);

describe("decodeStakeError", () => {
  it("maps an EIP-1193 user rejection", () => {
    expect(decodeStakeError({ code: "ACTION_REJECTED" })).toBe(
      "Transaction rejected in wallet."
    );
  });

  it("maps an insufficient-funds message to the native gas currency", () => {
    expect(decodeStakeError({ message: "insufficient funds for gas" })).toMatch(
      /Not enough \w+ to cover gas\./
    );
  });

  it("decodes a known custom Solidity error from revert data", () => {
    const data = iface.encodeErrorResult("Staker__InvalidAddress", []);
    expect(decodeStakeError({ data })).toBe(
      "Invalid address (zero address not allowed)."
    );
  });

  it("falls back to reason then message", () => {
    expect(decodeStakeError({ reason: "boom" })).toBe("boom");
    expect(decodeStakeError({})).toBe("Transaction failed.");
  });
});
