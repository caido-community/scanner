import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import emailDisclosureScan from "./index";

describe("Email Disclosure Check", () => {
  it("should detect email addresses in response", async () => {
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
      body: "Contact us at admin@example.com for support",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Email Address Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect multiple email addresses", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Contact admin@example.com or support@company.org for help",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Email Address Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect international domain emails", async () => {
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
      body: "Contact us at user@example.co.uk",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Email Address Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run on non-200 responses due to when clause", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "4",
      code: 404,
      headers: {},
      body: "Contact us at admin@example.com for support",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
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

  it("should not trigger on content without emails", async () => {
    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "5",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Welcome to our website",
    });

    const executionHistory = await runCheck(
      emailDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "email-disclosure",
        targetRequestId: "5",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });
});
