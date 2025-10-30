import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import pathRelativeStylesheetCheck from "./index";

const executeCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-path-css",
    host: "example.com",
    method: "GET",
    path: "/app/page",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-path-css",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body,
  });

  const execution = await runCheck(pathRelativeStylesheetCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Path-relative stylesheet import check", () => {
  it("flags link elements with path-relative href", async () => {
    const findings = await executeCheck(
      '<html><head><link rel="stylesheet" href="css/main.css"></head></html>',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Path-relative stylesheet import",
      severity: "low",
    });
  });

  it("flags @import rules with relative paths", async () => {
    const findings = await executeCheck(
      '<style>@import url("styles/theme.css");</style>',
    );

    expect(findings).toHaveLength(1);
  });

  it("does not flag absolute href values", async () => {
    const findings = await executeCheck(
      '<html><head><link rel="stylesheet" href="/static/app.css"></head></html>',
    );

    expect(findings).toHaveLength(0);
  });

  it("does not flag absolute import values", async () => {
    const findings = await executeCheck(
      '<style>@import "https://cdn.example.com/styles.css";</style>',
    );

    expect(findings).toHaveLength(0);
  });
});
