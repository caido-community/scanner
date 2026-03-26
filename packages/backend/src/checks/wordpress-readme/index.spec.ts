import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import wordpressReadmeCheck from ".";

describe("wordpress-readme check", () => {
  it("should detect WordPress readme.html", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/index.php",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: '<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2"></head><body><h1>WordPress</h1><p>Version 6.4.2</p><link href="/wp-includes/style.css"></body></html>',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(wordpressReadmeCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "WordPress Readme Exposed",
      severity: "info",
    });
  });

  it("should not detect when readme.html returns 404", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/index.php",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 404,
        headers: {},
        body: "Not Found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(wordpressReadmeCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });

  it("should not detect when body does not mention WordPress", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/index.php",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<!DOCTYPE html><html><body><h1>Welcome to My Application</h1></body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(wordpressReadmeCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });

  it("should not detect when body only mentions wordpress without specific indicators", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/index.php",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<!DOCTYPE html><html><body><p>This page mentions WordPress in passing.</p></body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(wordpressReadmeCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });
});
