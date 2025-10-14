import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import sqliteErrorBasedCheck from "./index";

describe("SQLite Error-Based SQL Injection Check", () => {
  it("should detect SQLite error-based SQL injection vulnerability", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "q=test'",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: 'near "test\'": syntax error',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'q'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect SQLite constraint error", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/login",
      query: "username=admin&password=test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "3",
        host: "example.com",
        method: "GET",
        path: "/login",
        query: "username=admin'&password=test",
      });

      const mockResponse = createMockResponse({
        id: "3",
        code: 500,
        headers: { "content-type": ["text/html"] },
        body: "FOREIGN KEY constraint failed",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'username'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect SQLite syntax error", async () => {
    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/api/users",
      query: "id=1",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "4",
        host: "example.com",
        method: "GET",
        path: "/api/users",
        query: "id=1'",
      });

      const mockResponse = createMockResponse({
        id: "4",
        code: 200,
        headers: { "content-type": ["application/json"] },
        body: '{"error": "no such table: users"}',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'id'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when no parameters are present", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/static/page.html",
    });

    const executionHistory = await runCheck(sqliteErrorBasedCheck, [
      { request, response: undefined },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should find no issues when no SQLite errors are present", async () => {
    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "6",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "q=test'",
      });

      const mockResponse = createMockResponse({
        id: "6",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html>Search results for: test</html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "5",
        status: "completed",
      },
    ]);

    // Should not have any findings in any step
    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });

  it("should detect SQLite3::SQLException error", async () => {
    const request = createMockRequest({
      id: "6",
      host: "example.com",
      method: "GET",
      path: "/api/data",
      query: "filter=active",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "7",
        host: "example.com",
        method: "GET",
        path: "/api/data",
        query: "filter=active'",
      });

      const mockResponse = createMockResponse({
        id: "7",
        code: 500,
        headers: { "content-type": ["text/html"] },
        body: "database schema has changed",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'filter'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect SQLite syntax error with regex pattern", async () => {
    const request = createMockRequest({
      id: "7",
      host: "example.com",
      method: "GET",
      path: "/api/search",
      query: "term=test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "8",
        host: "example.com",
        method: "GET",
        path: "/api/search",
        query: "term=test'",
      });

      const mockResponse = createMockResponse({
        id: "8",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: 'near "test\'": syntax error',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'term'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect SQLite database corruption error", async () => {
    const request = createMockRequest({
      id: "8",
      host: "example.com",
      method: "GET",
      path: "/api/data",
      query: "id=1",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "9",
        host: "example.com",
        method: "GET",
        path: "/api/data",
        query: "id=1'",
      });

      const mockResponse = createMockResponse({
        id: "9",
        code: 500,
        headers: { "content-type": ["text/html"] },
        body: "database disk image is malformed",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "8",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'id'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect SQLite no such column error", async () => {
    const request = createMockRequest({
      id: "9",
      host: "example.com",
      method: "GET",
      path: "/api/search",
      query: "field=value",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "10",
        host: "example.com",
        method: "GET",
        path: "/api/search",
        query: "field=value'",
      });

      const mockResponse = createMockResponse({
        id: "10",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "no such column: invalid_column",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      sqliteErrorBasedCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "sqlite-error-based-sqli",
        targetRequestId: "9",
        status: "completed",
        steps: [
          {
            stepName: "findParameters",
            findings: [],
            result: "continue",
          },
          {
            stepName: "testPayloads",
            findings: [
              {
                name: "SQLite Error-Based SQL Injection in parameter 'field'",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });
});
