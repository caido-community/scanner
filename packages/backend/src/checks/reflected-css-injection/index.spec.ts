import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import reflectedCssInjectionCheck from "./index";

const decodeQuery = (query: string): string => {
  try {
    return decodeURIComponent(query);
  } catch {
    return query;
  }
};

const extractStyleNeedle = (query: string): string | undefined => {
  const decodedQuery = decodeQuery(query);
  return decodedQuery.match(/scanner-css-[a-z0-9]+\.invalid/)?.[0];
};

const extractClassToken = (query: string): string | undefined => {
  const decodedQuery = decodeQuery(query);
  return decodedQuery.match(/(scanner-css-[a-z0-9]+)(?!\.invalid)/)?.[1];
};

const extractProbeToken = (query: string): string | undefined => {
  const decodedQuery = decodeQuery(query);
  return decodedQuery.match(/scanner-css-[a-z0-9]+(?:\.invalid)?/)?.[0];
};

const createSentRequest = ({
  id,
  specQuery,
}: {
  id: string;
  specQuery: string;
}) => {
  return createMockRequest({
    id,
    host: "example.com",
    method: "GET",
    path: "/page",
    query: specQuery,
  });
};

describe("reflected-css-injection check", () => {
  it("should detect reflected CSS injection in style tags", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "theme=red",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html><style>.box{color:red;}</style><body></body></html>",
      },
    });

    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: (spec) => {
        const styleNeedle =
          extractStyleNeedle(spec.getQuery()) ?? "scanner-css-default.invalid";

        const request = createSentRequest({
          id: "2",
          specQuery: spec.getQuery(),
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: `<html><style>.box{color:red;${styleNeedle}}</style><body></body></html>`,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Reflected CSS Injection in parameter 'theme'",
      severity: "medium",
    });
  });

  it("should detect reflected CSS injection in style attributes", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "color=blue",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: '<html><div style="color: blue">hello</div></html>',
      },
    });

    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: (spec) => {
        const styleNeedle =
          extractStyleNeedle(spec.getQuery()) ?? "scanner-css-default.invalid";

        const request = createSentRequest({
          id: "2",
          specQuery: spec.getQuery(),
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: `<html><div style="color:red;${styleNeedle}">hello</div></html>`,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Reflected CSS Injection in parameter 'color'",
      severity: "medium",
    });
  });

  it("should detect reflected class attribute injection with low severity", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "theme=blue",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: '<html><div class="theme-blue">hello blue</div></html>',
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: (spec) => {
        sendCallCount += 1;
        const decodedQuery = decodeQuery(spec.getQuery());
        const requestID = `${sendCallCount + 1}`;
        const request = createSentRequest({
          id: requestID,
          specQuery: spec.getQuery(),
        });

        if (decodedQuery.includes(".invalid")) {
          const response = createMockResponse({
            id: requestID,
            code: 200,
            headers: { "content-type": ["text/html"] },
            body: "<html><div>safe</div></html>",
          });
          return Promise.resolve({ request, response });
        }

        const classToken =
          extractClassToken(spec.getQuery()) ?? "scanner-css-low";
        const response = createMockResponse({
          id: requestID,
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: `<html><div class="${classToken}">safe</div></html>`,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Reflected CSS Injection in parameter 'theme'",
      severity: "low",
    });
  });

  it("should find no issues when probe is reflected outside CSS contexts", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "q=hello",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html><body>hello</body></html>",
      },
    });

    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: (spec) => {
        const token = extractProbeToken(spec.getQuery()) ?? "scanner-css-none";

        const request = createSentRequest({
          id: "2",
          specQuery: spec.getQuery(),
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: `<html><body>${token}</body></html>`,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should find no issues when sending the probe fails", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "theme=red",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html><style>.box{color:red;}</style><body></body></html>",
      },
    });

    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: () => {
        throw new Error("request failed");
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should find no issues when probe response status code is not 200", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "theme=red",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html><style>.box{color:red;}</style><body></body></html>",
      },
    });

    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: (spec) => {
        const styleNeedle =
          extractStyleNeedle(spec.getQuery()) ?? "scanner-css-default.invalid";

        const request = createSentRequest({
          id: "2",
          specQuery: spec.getQuery(),
        });
        const response = createMockResponse({
          id: "2",
          code: 302,
          headers: { "content-type": ["text/html"] },
          body: `<html><style>.box{color:red;${styleNeedle}}</style><body></body></html>`,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should find no issues when probe response contains invalid html", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "theme=red",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html><style>.box{color:red;}</style><body></body></html>",
      },
    });

    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: (spec) => {
        const request = createSentRequest({
          id: "2",
          specQuery: spec.getQuery(),
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "<html><style>\u0000",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not run on non-HTML targets", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "q=hello",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["application/json"] },
        body: '{"q":"hello"}',
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: () => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/page",
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "<html></html>",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });

  it("should not run when target status code is not 200", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "q=hello",
      },
      response: {
        id: "1",
        code: 302,
        headers: { "content-type": ["text/html"] },
        body: "<html><body>hello</body></html>",
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: () => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/page",
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "<html></html>",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });

  it("should not send probes when no reflected parameters are found", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "q=hello",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "<html><body>no reflection</body></html>",
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(reflectedCssInjectionCheck, target, {
      sendHandler: () => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/page",
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "<html></html>",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });
});
