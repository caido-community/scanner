import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import multipleContentTypesCheck from "./index";

const buildTarget = (headers: Record<string, string[]>) => {
  const request = createMockRequest({
    id: "req-1",
    host: "example.com",
    method: "GET",
    path: "/resource",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-1",
    code: 200,
    headers,
    body: "<html></html>",
  });

  return { request, response };
};

const collectFindings = async (
  headers: Record<string, string[]>,
): Promise<unknown[]> => {
  const target = buildTarget(headers);
  const execution = await runCheck(multipleContentTypesCheck, [target]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Multiple Content-Type headers check", () => {
  it("reports when multiple distinct content types are present", async () => {
    const findings = await collectFindings({
      "content-type": ["text/html", "application/json"],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Multiple Content-Type headers detected",
      severity: "medium",
    });
  });

  it("reports when multiple content types are comma-separated in a single header", async () => {
    const findings = await collectFindings({
      "content-type": ["text/html, application/json"],
    });

    expect(findings).toHaveLength(1);
  });

  it("does not report when only one content type is present", async () => {
    const findings = await collectFindings({
      "content-type": ["text/html"],
    });

    expect(findings).toHaveLength(0);
  });

  it("does not report duplicate identical content types", async () => {
    const findings = await collectFindings({
      "content-type": ["text/html", "text/html"],
    });

    expect(findings).toHaveLength(0);
  });
});
