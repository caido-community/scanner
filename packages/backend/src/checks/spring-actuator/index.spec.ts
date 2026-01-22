import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import springActuatorCheck from "./index";

describe("spring-actuator check", () => {
  it("should detect exposed actuator env endpoint", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/api/actuator/env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/json"],
        },
        body: JSON.stringify({
          activeProfiles: ["production"],
          propertySources: [
            {
              name: "systemProperties",
              properties: {
                "java.runtime.name": { value: "OpenJDK Runtime Environment" },
              },
            },
          ],
        }),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: "Spring Actuator Environment",
      severity: "critical",
    });
  });

  it("should detect exposed actuator heapdump endpoint", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.php",
    });

    const heapContent =
      "JAVA PROFILE 1.0.2" +
      "\x00".repeat(100) +
      "java.lang.String" +
      "\x00".repeat(900);

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/actuator/heapdump",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/octet-stream"],
        },
        body: heapContent,
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: "Spring Actuator Heapdump",
      severity: "critical",
    });
  });

  it("should detect exposed actuator gateway routes endpoint", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/resource",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/api/actuator/gateway/routes",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/json"],
        },
        body: JSON.stringify([
          {
            route_id: "api-service",
            predicate: "Paths: [/api/**]",
            uri: "lb://api-service",
          },
        ]),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: "Spring Actuator Gateway Routes",
      severity: "critical",
    });
  });

  it("should not detect when endpoint returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/api/actuator/env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 404,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<html><body>Not Found</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should not detect when response is not valid actuator content", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/test",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/api/actuator/env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/json"],
        },
        body: JSON.stringify({ message: "Welcome to the API" }),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should not detect heapdump with wrong content type", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/actuator/heapdump",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "JAVA PROFILE 1.0.2" + "x".repeat(1000),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should not detect heapdump with small body", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/actuator/heapdump",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/octet-stream"],
        },
        body: "JAVA PROFILE 1.0.2",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      springActuatorCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should use correct base path from request", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/deep/nested/path/resource.json",
    });

    let capturedPath = "";
    const sendHandler = (spec: { getPath: () => string }) => {
      capturedPath = spec.getPath();

      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: capturedPath,
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 404,
        headers: {},
        body: "Not found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    await runCheck(springActuatorCheck, [{ request, response: undefined }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(capturedPath).toContain("/deep/nested/path/");
  });

  it("should test bypass techniques on higher aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/test",
    });

    const testedPaths: string[] = [];
    const sendHandler = (spec: { getPath: () => string }) => {
      testedPaths.push(spec.getPath());

      const mockRequest = createMockRequest({
        id: String(testedPaths.length + 1),
        host: "example.com",
        method: "GET",
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: String(testedPaths.length + 1),
        code: 404,
        headers: {},
        body: "Not found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    await runCheck(springActuatorCheck, [{ request, response: undefined }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.HIGH },
    });

    const hasDoubleSlash = testedPaths.some((p) => p.includes("//actuator"));
    const hasUrlEncoded = testedPaths.some((p) => p.includes("%2F"));
    const hasTomcatBypass = testedPaths.some((p) => p.includes("..;"));

    expect(hasDoubleSlash).toBe(true);
    expect(hasUrlEncoded).toBe(true);
    expect(hasTomcatBypass).toBe(true);
  });
});
