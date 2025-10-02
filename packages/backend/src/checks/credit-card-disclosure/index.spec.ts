import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import creditCardDisclosureScan from "./index";

describe("Credit Card Disclosure Check", () => {
  it("should detect credit card numbers in response", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "User credit card: 4111111111111111",
    });

    const executionHistory = await runCheck(
      creditCardDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "credit-card-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Credit Card Number Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain("4111111111111111");
  });

  it("should not run on non-200 responses due to when clause", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "2",
      code: 404,
      headers: {},
      body: "User credit card: 4111-1111-1111-1111",
    });

    const executionHistory = await runCheck(
      creditCardDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    // With the when clause, the check should be skipped entirely for non-200 responses
    // When skipped, the check doesn't appear in execution history at all
    expect(executionHistory).toEqual([]);
  });

  it("should not trigger on normal content", async () => {
    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Welcome to our website",
    });

    const executionHistory = await runCheck(
      creditCardDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "credit-card-disclosure",
        targetRequestId: "3",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });
});
