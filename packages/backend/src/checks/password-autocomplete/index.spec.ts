import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import passwordAutocompleteCheck from "./index";

const runAutocompleteCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-pass-autocomplete",
    host: "example.com",
    method: "GET",
    path: "/login",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-pass-autocomplete",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body,
  });

  const execution = await runCheck(passwordAutocompleteCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Password autocomplete check", () => {
  it("flags password inputs without autocomplete attribute", async () => {
    const findings = await runAutocompleteCheck(
      '<input type="password" name="password">',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Password field with autocomplete enabled",
      severity: "low",
    });
  });

  it("flags password inputs with autocomplete set to on", async () => {
    const findings = await runAutocompleteCheck(
      '<input type="password" name="password" autocomplete="on">',
    );

    expect(findings).toHaveLength(1);
  });

  it("does not flag password inputs with autocomplete off", async () => {
    const findings = await runAutocompleteCheck(
      '<input type="password" name="password" autocomplete="off">',
    );

    expect(findings).toHaveLength(0);
  });

  it("does not flag password inputs with autocomplete new-password", async () => {
    const findings = await runAutocompleteCheck(
      '<input type="password" name="password" autocomplete="new-password">',
    );

    expect(findings).toHaveLength(0);
  });
});
