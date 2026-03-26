import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import check from ".";

const XOXB_PREFIX = "xoxb-";
const XOXP_PREFIX = "xoxp-";
const FAKE_MID = "0000000000000-0000000000000-";
const FAKE_SUFFIX = "FAKETESTVALUENOTREAL000000";
const XOXB_TOKEN = XOXB_PREFIX + FAKE_MID + FAKE_SUFFIX;
const XOXP_TOKEN = XOXP_PREFIX + FAKE_MID + FAKE_SUFFIX;
const WEBHOOK_PREFIX = "https://hooks.slack.com/services/";
const WEBHOOK_TOKEN =
  WEBHOOK_PREFIX + "T00000000/B00000000/ABCDEFGHIJKLMNOPQRSTUVWX";

describe("slack-token-disclosure", () => {
  it("does not run on non-200 response", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 403,
          body: XOXB_TOKEN,
        }),
      },
    ]);
    expect(history).toHaveLength(0);
  });

  it("finds nothing on clean response", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: "normal content without secrets",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(0);
  });

  it("detects xoxb bot token", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: `token=${XOXB_TOKEN}`,
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects xoxp user token", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: `token=${XOXP_TOKEN}`,
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects webhook URL", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: `webhook=${WEBHOOK_TOKEN}`,
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });
});
