import {
  createMockRequest,
  createMockResponse,
  runCheck,
  type SendHandler,
} from "engine";
import { describe, expect, it } from "vitest";

import traceCheck from "./index";

const TRACE_HEADER = "X-Trace-Detection";

type HandlerConfig = {
  status: number;
  echoMarker?: boolean;
};

const buildSendHandler = (config: HandlerConfig): SendHandler => {
  return (spec) => {
    const body =
      config.echoMarker === true
        ? [
            `TRACE ${spec.getPath()} HTTP/1.1`,
            `${TRACE_HEADER}: ${spec.getHeader(TRACE_HEADER)?.[0] ?? ""}`,
          ].join("\r\n")
        : "TRACE disabled";

    const mockRequest = createMockRequest({
      id: "trace-probe",
      host: spec.getHost(),
      method: spec.getMethod(),
      path: spec.getPath(),
      query: spec.getQuery(),
      headers: spec.getHeaders(),
    });

    const mockResponse = createMockResponse({
      id: "trace-response",
      code: config.status,
      headers: { "content-type": ["message/http"] },
      body,
    });

    return Promise.resolve({ request: mockRequest, response: mockResponse });
  };
};

describe("HTTP TRACE enabled check", () => {
  it("reports when TRACE is enabled and echoes headers", async () => {
    const targetRequest = createMockRequest({
      id: "target-1",
      host: "example.com",
      method: "GET",
      path: "/trace",
      headers: { Host: ["example.com"] },
    });

    const targetResponse = createMockResponse({
      id: "target-resp-1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "",
    });

    const execution = await runCheck(
      traceCheck,
      [{ request: targetRequest, response: targetResponse }],
      { sendHandler: buildSendHandler({ status: 200, echoMarker: true }) },
    );

    const findings =
      execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("medium");
  });

  it("does not report when TRACE returns 405", async () => {
    const targetRequest = createMockRequest({
      id: "target-2",
      host: "example.com",
      method: "GET",
      path: "/trace",
      headers: { Host: ["example.com"] },
    });

    const targetResponse = createMockResponse({
      id: "target-resp-2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "",
    });

    const execution = await runCheck(
      traceCheck,
      [{ request: targetRequest, response: targetResponse }],
      { sendHandler: buildSendHandler({ status: 405, echoMarker: false }) },
    );

    const findings =
      execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
    expect(findings).toHaveLength(0);
  });

  it("does not report when headers are not echoed", async () => {
    const targetRequest = createMockRequest({
      id: "target-3",
      host: "example.com",
      method: "GET",
      path: "/trace",
      headers: { Host: ["example.com"] },
    });

    const targetResponse = createMockResponse({
      id: "target-resp-3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "",
    });

    const execution = await runCheck(
      traceCheck,
      [{ request: targetRequest, response: targetResponse }],
      { sendHandler: buildSendHandler({ status: 200, echoMarker: false }) },
    );

    const findings =
      execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
