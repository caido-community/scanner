import { mockTarget, testCheck } from "engine";
import { describe, expect, it } from "vitest";

import sourcemapCheck from "./index";

describe("sourcemap-disclosure check", () => {
  it("should not run when response is not JavaScript", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page.html",
      },
      response: {
        id: "1",
        code: 200,
        headers: {
          "content-type": ["text/html"],
        },
        body: "<html><body>Hello</body></html>",
      },
    });

    const { findings } = await testCheck(sourcemapCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should not detect when no source map reference exists", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/app.js",
      },
      response: {
        id: "1",
        code: 200,
        headers: {
          "content-type": ["application/javascript"],
        },
        body: 'var x = 1; console.log("hello");',
      },
    });

    const { findings } = await testCheck(sourcemapCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should detect source map via SourceMap header", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/app.js",
      },
      response: {
        id: "1",
        code: 200,
        headers: {
          "content-type": ["application/javascript"],
          SourceMap: ["/app.js.map"],
        },
        body: 'var x = 1; console.log("hello");',
      },
    });

    const { findings } = await testCheck(sourcemapCheck, target);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Source Map Disclosed via Header",
      severity: "medium",
    });
  });

  it("should detect source map via sourceMappingURL comment", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/app.js",
      },
      response: {
        id: "1",
        code: 200,
        headers: {
          "content-type": ["application/javascript"],
        },
        body: "var x = 1;\n//# sourceMappingURL=app.js.map",
      },
    });

    const { findings } = await testCheck(sourcemapCheck, target);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Source Map Disclosed via Comment",
      severity: "medium",
    });
  });
});
