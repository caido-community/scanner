import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
  Severity,
} from "engine";
import { describe, expect, it } from "vitest";

import { defineResponseRegexCheck } from "./check";

describe("defineResponseRegexCheck", () => {
  it("should detect matches and generate findings", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [/error/i, /warning/i],
      toFindings: (matches, context) => [
        {
          name: "Test Finding",
          description: `Found patterns: ${matches.join(", ")}`,
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "test-check",
        name: "Test Check",
        description: "A test check",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

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
      body: "This is an error message",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "test-check",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Test Finding",
                description: "Found patterns: error",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should handle multiple pattern matches", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [/error/i, /warning/i, /debug/i],
      toFindings: (matches, context) => [
        {
          name: "Multiple Patterns Found",
          description: `Found ${matches.length} patterns: ${matches.join(", ")}`,
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "multi-pattern-check",
        name: "Multi Pattern Check",
        description: "A test check for multiple patterns",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

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
      body: "This is an error message with a warning and debug info",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "multi-pattern-check",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Multiple Patterns Found",
                description: expect.stringContaining("Found 3 patterns"),
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
    const testCheck = defineResponseRegexCheck({
      patterns: [/error/i],
      toFindings: (matches, context) => [
        {
          name: "Error Found",
          description: "Found error pattern",
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "non-200-test",
        name: "Non-200 Test",
        description: "A test check for non-200 responses",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "3",
      code: 404,
      headers: {},
      body: "This is an error message",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toEqual([]);
  });

  it("should not trigger when no patterns match", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [/error/i, /warning/i],
      toFindings: (matches, context) => [
        {
          name: "Pattern Found",
          description: "Found pattern",
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "no-match-test",
        name: "No Match Test",
        description: "A test check for no matches",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

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
      body: "This is a normal message without any patterns",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "no-match-test",
        targetRequestId: "4",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });

  it("should not run on undefined response due to when clause", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [/error/i],
      toFindings: (matches, context) => [
        {
          name: "Error Found",
          description: "Found error pattern",
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "undefined-response-test",
        name: "Undefined Response Test",
        description: "A test check for undefined response",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    // Create a mock response with 500 status to test the when clause
    const response = createMockResponse({
      id: "5",
      code: 500,
      headers: {},
      body: "This is an error message",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toEqual([]);
  });

  it("should handle empty patterns array", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [],
      toFindings: (matches, context) => [
        {
          name: "Pattern Found",
          description: "Found pattern",
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "empty-patterns-test",
        name: "Empty Patterns Test",
        description: "A test check for empty patterns",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

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
      body: "This is a message",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "empty-patterns-test",
        targetRequestId: "6",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });

  it("should handle case-insensitive patterns", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [/ERROR/i, /WARNING/i],
      toFindings: (matches, context) => [
        {
          name: "Case Insensitive Match",
          description: `Found patterns: ${matches.join(", ")}`,
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "case-insensitive-test",
        name: "Case Insensitive Test",
        description: "A test check for case insensitive patterns",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

    const request = createMockRequest({
      id: "7",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "7",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "This is an error message",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "case-insensitive-test",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Case Insensitive Match",
                description: "Found patterns: error",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should handle complex regex patterns", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [
        /\b\d{3}-\d{2}-\d{4}\b/, // SSN pattern
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email pattern
      ],
      toFindings: (matches, context) => [
        {
          name: "Sensitive Data Found",
          description: `Found sensitive data: ${matches.join(", ")}`,
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "complex-regex-test",
        name: "Complex Regex Test",
        description: "A test check for complex regex patterns",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

    const request = createMockRequest({
      id: "8",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "8",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "User SSN: 123-45-6789, Contact: admin@example.com",
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "complex-regex-test",
        targetRequestId: "8",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Sensitive Data Found",
                description: expect.stringContaining("Found sensitive data"),
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should deduplicate matches", async () => {
    const testCheck = defineResponseRegexCheck({
      patterns: [/test/gi], // Global flag to find all matches
      toFindings: (matches, context) => [
        {
          name: "Duplicate Test",
          description: `Found ${matches.length} matches: ${matches.join(", ")}`,
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
      metadata: {
        id: "dedupe-test",
        name: "Dedupe Test",
        description: "A test check for deduplication",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

    const request = createMockRequest({
      id: "9",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "9",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "test test test", // Multiple identical matches
    });

    const executionHistory = await runCheck(
      testCheck,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "dedupe-test",
        targetRequestId: "9",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Duplicate Test",
                description: "Found 1 matches: test", // Should be deduplicated
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should pass correct runtime context to toFindings", async () => {
    let capturedContext: unknown = null;

    const testCheck = defineResponseRegexCheck({
      patterns: [/test/i],
      toFindings: (matches, context) => {
        capturedContext = context;
        return [
          {
            name: "Context Test",
            description: "Testing context",
            severity: Severity.INFO,
            correlation: {
              requestID: context.target.request.getId(),
              locations: [],
            },
          },
        ];
      },
      metadata: {
        id: "context-test",
        name: "Context Test",
        description: "A test check for context",
        type: "passive",
        tags: ["test"],
        severities: [Severity.INFO],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
      },
    });

    const request = createMockRequest({
      id: "10",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "10",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "This is a test message",
    });

    await runCheck(testCheck, [{ request, response }], {
      sendHandler: () => Promise.resolve({ request, response }),
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(capturedContext).toBeDefined();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((capturedContext as any).target.request.getId()).toBe("10");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((capturedContext as any).target.response.getCode()).toBe(200);
  });
});
