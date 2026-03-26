import { mockTarget, testCheck } from "engine";
import { describe, expect, it } from "vitest";

import check from ".";

describe("subdomain-takeover", () => {
  it("does not run on 200 response", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        body: "There isn't a GitHub Pages site here",
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(0);
  });

  it("finds nothing on generic 404", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 404,
        body: "Page not found",
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(0);
  });

  it("detects GitHub Pages takeover", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "sub.example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 404,
        body: "There isn't a GitHub Pages site here.",
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("Subdomain Takeover");
  });

  it("detects S3 bucket takeover", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "assets.example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 404,
        body: "<Error><Code>NoSuchBucket</Code></Error>",
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(1);
  });

  it("detects Shopify takeover", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "shop.example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 404,
        body: "Sorry, this shop is currently unavailable.",
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(1);
  });

  it("detects Heroku takeover", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "app.example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 404,
        body: "There is no app configured at that hostname",
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(1);
  });

  it("does not run on body larger than 10KB", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 404,
        body: "NoSuchBucket" + "x".repeat(10_001),
      },
    });
    const { findings } = await testCheck(check, target);
    expect(findings).toHaveLength(0);
  });
});
