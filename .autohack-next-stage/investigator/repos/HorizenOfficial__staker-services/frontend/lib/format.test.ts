import { describe, expect, it } from "vitest";
import { parseEther } from "ethers";
import {
  estimateApr,
  formatPct,
  formatToken,
  truncateAddress,
} from "./format";

describe("formatToken", () => {
  it("groups thousands and trims trailing fraction zeros", () => {
    expect(formatToken(parseEther("1234.5000"))).toBe("1,234.5");
  });

  it("drops the fraction entirely when it rounds away", () => {
    expect(formatToken(parseEther("1000"))).toBe("1,000");
  });

  it("truncates (does not round) to the requested precision", () => {
    expect(formatToken(parseEther("1.23456"))).toBe("1.2345");
  });

  it("formats zero", () => {
    expect(formatToken(0n)).toBe("0");
  });
});

describe("estimateApr", () => {
  it("returns null when nothing is staked", () => {
    expect(estimateApr(1n, 0n)).toBeNull();
  });

  it("computes a 100% APR when annualized daily amount equals total staked", () => {
    const totalStaked = parseEther("365");
    const dailyAmount = totalStaked / 365n;
    expect(estimateApr(dailyAmount, totalStaked)).toBeCloseTo(100, 0);
  });
});

describe("formatPct", () => {
  it("renders a dash for null", () => {
    expect(formatPct(null)).toBe("—");
  });

  it("fixes to the requested digits", () => {
    expect(formatPct(12.3456)).toBe("12.35%");
  });
});

describe("truncateAddress", () => {
  it("keeps the 0x prefix and last four", () => {
    expect(truncateAddress("0x1234567890abcdef1234567890abcdef12345678")).toBe(
      "0x1234…5678"
    );
  });

  it("returns empty string for empty input", () => {
    expect(truncateAddress("")).toBe("");
  });
});
