import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import linkManipulationCheck from "./index";

describe("link-manipulation check", () => {
  it("should not run when response is not HTML", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/data",
      query: "redirect=https://evil.com",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"redirect": "https://evil.com"}',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toEqual([]);
  });

  it("should not run when response body is empty", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "url=https://evil.com",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: "",
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toEqual([]);
  });

  it("should find no issues when no parameters are present", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><a href="https://example.com">Link</a></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when parameter value is too short", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "url=abc",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><a href="abc">Link</a></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when parameter is not reflected in href/src", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "search=hello+world",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><p>hello world</p><a href="https://example.com">Link</a></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect reflection in href attribute of anchor tag", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "redirect=https://evil.com",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><a href="https://evil.com">Click here</a></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'redirect'",
                severity: "high",
                correlation: {
                  requestID: "1",
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect reflection in src attribute of img tag", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "image=https://evil.com/malicious.jpg",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><img src="https://evil.com/malicious.jpg"></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'image'",
                severity: "high",
                correlation: {
                  requestID: "1",
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect reflection in src attribute of script tag", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "script=https://attacker.com/evil.js",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><script src="https://attacker.com/evil.js"></script></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'script'",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect reflection in src attribute of iframe tag", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "frame=https://phishing.com/fake-login",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><iframe src="https://phishing.com/fake-login"></iframe></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'frame'",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect reflection in href attribute of link tag", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "stylesheet=https://evil.com/malicious.css",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><head><link rel="stylesheet" href="https://evil.com/malicious.css"></head></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'stylesheet'",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should report only once per parameter even if reflected multiple times", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "url=https://evil.com",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: `<html><body>
        <a href="https://evil.com">Link 1</a>
        <a href="https://evil.com/page">Link 2</a>
        <img src="https://evil.com/image.jpg">
      </body></html>`,
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'url'",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);

    const findings = executionHistory[0]?.steps[0]?.findings;
    expect(findings).toHaveLength(1);
  });

  it("should detect multiple vulnerable parameters", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "redirect=https://evil.com&image=https://attacker.com/img.jpg",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: `<html><body>
        <a href="https://evil.com">Link</a>
        <img src="https://attacker.com/img.jpg">
      </body></html>`,
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            result: "done",
          },
        ],
      },
    ]);

    const findings = executionHistory[0]?.steps[0]?.findings;
    expect(findings).toHaveLength(2);
  });

  it("should detect partial reflection in URL", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "callback=attacker.com",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><a href="https://attacker.com/callback">Link</a></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'callback'",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should handle POST body parameters", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/page",
      query: "",
      headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
      body: "redirect=https://evil.com",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["text/html"] },
      body: '<html><body><a href="https://evil.com">Link</a></body></html>',
    });

    const executionHistory = await runCheck(linkManipulationCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "link-manipulation",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "analyze",
            findings: [
              {
                name: "Link Manipulation in parameter 'redirect'",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });
});
