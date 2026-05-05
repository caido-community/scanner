import { vi } from "vitest";

export const createMockSDK = () => ({
  console: {
    log: vi.fn(),
    error: vi.fn(),
  },
  meta: {
    path: vi.fn().mockReturnValue("/tmp/scanner-test"),
    id: vi.fn().mockReturnValue("scanner"),
    db: vi.fn(),
    assetsPath: vi.fn(),
    version: vi.fn().mockReturnValue("0.0.0"),
    updateAvailable: vi.fn(),
  },
  api: {
    send: vi.fn(),
    register: vi.fn(),
  },
  env: {
    getVar: vi.fn(),
    getVars: vi.fn().mockReturnValue([]),
    setVar: vi.fn().mockResolvedValue(undefined),
  },
  events: {
    onInterceptRequest: vi.fn(),
    onInterceptResponse: vi.fn(),
    onProjectChange: vi.fn(),
    onUpstream: vi.fn(),
  },
  findings: { create: vi.fn() },
  requests: {
    send: vi.fn(),
    get: vi.fn(),
    inScope: vi.fn(),
  },
  replay: {},
  projects: { getCurrent: vi.fn() },
  scope: {},
  runtime: {},
  graphql: {},
  hostedFile: {},
  net: {},
});
