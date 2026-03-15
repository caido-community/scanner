import type { QueueTask } from "shared";
import { describe, expect, it } from "vitest";

import {
  formatHost,
  formatPathWithQuery,
  formatTaskId,
  getCheckDisplayNames,
} from "./utils";

const task: QueueTask = {
  id: "pscan-123",
  request: {
    id: "req-1",
    host: "example.com",
    port: 443,
    path: "/search",
    query: "q=test",
    method: "GET",
  },
  executedCheckIDs: ["application-errors"],
  createdAt: 10,
  status: "pending",
};

describe("queue utils", () => {
  it("strips the passive queue prefix from task ids", () => {
    expect(formatTaskId(task.id)).toBe("123");
  });

  it("hides default ports and keeps non-default ports", () => {
    expect(formatHost(task)).toBe("example.com");
    expect(
      formatHost({
        ...task,
        request: {
          ...task.request,
          port: 8443,
        },
      }),
    ).toBe("example.com:8443");
  });

  it("formats path with and without a query string", () => {
    expect(formatPathWithQuery(task)).toBe("/search?q=test");
    expect(
      formatPathWithQuery({
        ...task,
        request: {
          ...task.request,
          query: "",
        },
      }),
    ).toBe("/search");
  });

  it("maps check ids to names and falls back to raw ids", () => {
    expect(
      getCheckDisplayNames({
        checkIDs: ["application-errors", "missing-check"],
        checks: [
          {
            id: "application-errors",
            name: "Application Error Information Disclosure",
            description: "",
            tags: [],
            aggressivity: { minRequests: 0, maxRequests: 0 },
            type: "passive",
            severities: [],
          },
        ],
      }),
    ).toEqual(["Application Error Information Disclosure", "missing-check"]);
  });
});
