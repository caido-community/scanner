import type { Session } from "shared";
import { describe, expect, it, vi } from "vitest";

import { createMockSDK } from "../__tests__/mockSdk";
import { ScannerStore } from "../stores/scanner";

import {
  apiDeleteScanSession,
  apiGetScanSession,
  apiGetScanSessions,
} from "./scanner";

vi.mock("caido:utils", () => ({
  RequestSpec: class {},
}));

const session: Session = {
  kind: "Pending",
  id: "session-1",
  createdAt: 0,
  title: "Demo",
  requestIDs: ["req-1"],
  scanConfig: {
    aggressivity: "medium",
    scopeIDs: [],
    concurrentChecks: 1,
    concurrentRequests: 1,
    concurrentTargets: 1,
    requestsDelayMs: 0,
    scanTimeout: 60,
    checkTimeout: 60,
    severities: ["info"],
  },
};

describe("apiGetScanSession", () => {
  it("returns Ok when found", () => {
    vi.spyOn(ScannerStore, "get").mockReturnValue({
      getSession: () => session,
    } as unknown as ScannerStore);

    expect(apiGetScanSession(createMockSDK() as never, "session-1")).toEqual({
      kind: "Ok",
      value: session,
    });
  });

  it("returns Error when missing", () => {
    vi.spyOn(ScannerStore, "get").mockReturnValue({
      getSession: () => undefined,
    } as unknown as ScannerStore);

    const result = apiGetScanSession(createMockSDK() as never, "missing");
    expect(result.kind).toBe("Error");
  });
});

describe("apiGetScanSessions", () => {
  it("returns all sessions from the store", () => {
    vi.spyOn(ScannerStore, "get").mockReturnValue({
      listSessions: () => [session],
    } as unknown as ScannerStore);

    expect(apiGetScanSessions(createMockSDK() as never)).toEqual({
      kind: "Ok",
      value: [session],
    });
  });
});

describe("apiDeleteScanSession", () => {
  it("returns the boolean result from the store", () => {
    vi.spyOn(ScannerStore, "get").mockReturnValue({
      deleteSession: () => true,
    } as unknown as ScannerStore);

    expect(apiDeleteScanSession(createMockSDK() as never, "session-1")).toEqual(
      { kind: "Ok", value: true },
    );
  });
});
