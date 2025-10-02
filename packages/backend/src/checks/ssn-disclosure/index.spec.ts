import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import ssnDisclosureScan from "./index";

describe("SSN Disclosure Check", () => {
  it("should detect SSN with dashes in response", async () => {
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
      body: "User SSN: 123-45-6789",
    });

    const executionHistory = await runCheck(
      ssnDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "ssn-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Social Security Number Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not trigger on 9-digit numbers without separators (to avoid false positives)", async () => {
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
      body: "Product ID: 123456789",
    });

    const executionHistory = await runCheck(
      ssnDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "ssn-disclosure",
        targetRequestId: "2",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });

  it("should detect SSN with spaces", async () => {
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
      body: "User SSN: 123 45 6789",
    });

    const executionHistory = await runCheck(
      ssnDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "ssn-disclosure",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Social Security Number Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect SSN with dots", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "4",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "User SSN: 123.45.6789",
    });

    const executionHistory = await runCheck(
      ssnDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "ssn-disclosure",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Social Security Number Disclosed",
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
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "5",
      code: 404,
      headers: {},
      body: "User SSN: 123-45-6789",
    });

    const executionHistory = await runCheck(
      ssnDisclosureScan,
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

  it("should not trigger on content without SSN", async () => {
    const request = createMockRequest({
      id: "6",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "6",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Welcome to our website",
    });

    const executionHistory = await runCheck(
      ssnDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "ssn-disclosure",
        targetRequestId: "6",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });
});
