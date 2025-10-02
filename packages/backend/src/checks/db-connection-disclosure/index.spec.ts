import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import dbConnectionDisclosureScan from "./index";

describe("Database Connection Disclosure Check", () => {
  it("should detect MySQL connection string", async () => {
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
      body: "Database URL: mysql://user:password@localhost:3306/database",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "mysql://user:password@localhost:3306/database",
    );
  });

  it("should detect PostgreSQL connection string", async () => {
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
      body: "Database URL: postgresql://user:password@localhost:5432/database",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "postgresql://user:password@localhost:5432/database",
    );
  });

  it("should detect MongoDB connection string", async () => {
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
      body: "Database URL: mongodb://user:password@localhost:27017/database",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "mongodb://user:password@localhost:27017/database",
    );
  });

  it("should detect MongoDB SRV connection string", async () => {
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
      body: "Database URL: mongodb+srv://user:password@cluster.mongodb.net/database",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "mongodb+srv://user:password@cluster.mongodb.net/database",
    );
  });

  it("should detect SQL Server connection string", async () => {
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
      body: "Server=localhost;Database=mydb;User Id=user;Password=password",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "Server=localhost;Database=mydb;User Id=user;Password=password",
    );
  });

  it("should detect Oracle connection string", async () => {
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
      body: "Database URL: oracle://user:password@localhost:1521/database",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "oracle://user:password@localhost:1521/database",
    );
  });

  it("should detect Redis connection string", async () => {
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
      body: "Database URL: redis://user:password@localhost:6379",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "redis://user:password@localhost:6379",
    );
  });

  it("should detect JDBC connection string", async () => {
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
      body: "jdbc:mysql://localhost:3306/database;user=user;password=password",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "8",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "jdbc:mysql://localhost:3306/database;user=user;password=password",
    );
  });

  it("should detect generic database connection patterns", async () => {
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
      body: "database_url=postgresql://user:pass@localhost/db",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "9",
        status: "completed",
        steps: [
          {
            stepName: "scanResponse",
            findings: [
              {
                name: "Database Connection String Disclosed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding?.description).toContain(
      "postgresql://user:pass@localhost/db",
    );
  });

  it("should not run on non-200 responses due to when clause", async () => {
    const request = createMockRequest({
      id: "10",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "10",
      code: 404,
      headers: {},
      body: "Database URL: mysql://user:password@localhost:3306/database",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
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

  it("should not trigger on content without database connections", async () => {
    const request = createMockRequest({
      id: "11",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "11",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Welcome to our website",
    });

    const executionHistory = await runCheck(
      dbConnectionDisclosureScan,
      [{ request, response }],
      {
        sendHandler: () => Promise.resolve({ request, response }),
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "db-connection-disclosure",
        targetRequestId: "11",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });
});
