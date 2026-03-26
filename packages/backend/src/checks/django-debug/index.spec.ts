import { mockTarget, testCheck } from "engine";
import { describe, expect, it } from "vitest";

import djangoDebugCheck from "./index";

describe("django-debug check", () => {
  it("should not run when response code is less than 400", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should detect Django debug mode with DEBUG = True signature", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/nonexistent",
      },
      response: {
        id: "1",
        code: 404,
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body><h1>Page not found</h1><p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p></body></html>",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Django Debug Mode Enabled",
      severity: "medium",
    });
  });

  it("should detect Django debug mode with DisallowedHost", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
      },
      response: {
        id: "1",
        code: 400,
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body><h1>DisallowedHost at /test</h1><p>Invalid HTTP_HOST header</p></body></html>",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Django Debug Mode Enabled",
      severity: "medium",
    });
  });

  it("should detect Django exception signatures", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
      },
      response: {
        id: "1",
        code: 500,
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body>Traceback: django.core.exceptions.ImproperlyConfigured: ...</body></html>",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(1);
  });

  it("should not detect on generic 404 page", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/nonexistent",
      },
      response: {
        id: "1",
        code: 404,
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body><h1>404 Not Found</h1><p>The page you are looking for does not exist.</p></body></html>",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should not detect on generic 500 error page", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
      },
      response: {
        id: "1",
        code: 500,
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body><h1>Internal Server Error</h1></body></html>",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should detect DJANGO_SETTINGS_MODULE in error page", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
      },
      response: {
        id: "1",
        code: 500,
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body><h2>Environment:</h2><table><tr><td>DJANGO_SETTINGS_MODULE</td><td>myapp.settings</td></tr></table></body></html>",
      },
    });

    const { findings } = await testCheck(djangoDebugCheck, target);

    expect(findings).toHaveLength(1);
  });
});
