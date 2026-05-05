import type { CheckMetadata } from "shared";
import { describe, expect, it, vi } from "vitest";

import { createMockSDK } from "../__tests__/mockSdk";
import { ChecksStore } from "../stores/checks";

import { apiGetChecks } from "./checks";

describe("apiGetChecks", () => {
  it("returns metadata from the store", () => {
    const metadata: CheckMetadata = {
      id: "demo",
      name: "Demo",
      description: "",
      tags: [],
      type: "active",
      aggressivity: { minRequests: 1, maxRequests: 1 },
      severities: ["info"],
    };
    vi.spyOn(ChecksStore, "get").mockReturnValue({
      select: () => [metadata],
    } as unknown as ChecksStore);

    const result = apiGetChecks(createMockSDK() as never);

    expect(result).toEqual({ kind: "Ok", value: [metadata] });
  });

  it("returns Error on invalid options", () => {
    const result = apiGetChecks(
      createMockSDK() as never,
      { include: "not-an-array" } as never,
    );

    expect(result.kind).toBe("Error");
  });
});
