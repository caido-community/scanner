import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import unencryptedCheck from "./index";

describe("Unencrypted communications check", () => {
  it("raises finding for HTTP requests", async () => {
    const request = createMockRequest({
      id: "req-http",
      host: "example.com",
      method: "GET",
      path: "/",
      tls: false,
    });

    const response = createMockResponse({
      id: "res-http",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "OK",
    });

    const executionHistory = await runCheck(unencryptedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "unencrypted-communications",
        targetRequestId: "req-http",
        steps: [
          {
            stepName: "detectUnencrypted",
            findings: [
              {
                name: "Unencrypted HTTP communication",
                severity: "high",
              },
            ],
          },
        ],
      },
    ]);
  });

  it("does not flag HTTPS traffic", async () => {
    const request = createMockRequest({
      id: "req-https",
      host: "example.com",
      method: "GET",
      path: "/",
      tls: true,
    });

    const response = createMockResponse({
      id: "res-https",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "OK",
    });

    const executionHistory = await runCheck(unencryptedCheck, [
      { request, response },
    ]);

    const lastStep =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1];
    expect(lastStep?.findings ?? []).toHaveLength(0);
  });
});
