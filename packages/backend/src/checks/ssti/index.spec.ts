/**
 * Server-Side Template Injection (SSTI) Check Tests
 * 
 * Author: Amr Elsagaei
 * Website: amrelsagaei.com
 * Email: info@amrelsagaei.com
 */

import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import sstiCheck from "./index";

describe("SSTI Check", () => {
  describe("Mathematical Expression Detection", () => {
    it("should detect Jinja2 SSTI with {{7*7}} payload", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "name=test",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "Hello test", // Parameter reflected in response
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/search",
          query: "name=test{{7*7}}",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: {
            "Content-Type": ["text/html"],
          },
          body: "Hello test49", // Mathematical expression evaluated to 49
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      expect(executionHistory).toMatchObject([
        {
          checkId: "ssti",
          targetRequestId: "1",
          steps: [
            {
              stepName: "findReflectedParameters",
              result: "continue",
            },
            {
              stepName: "testMathematicalPayloads",
              findings: [
                {
                  name: "Server-Side Template Injection in parameter 'name'",
                  severity: "critical",
                  correlation: { requestID: "2" },
                },
              ],
              result: "done",
            },
          ],
          status: "completed",
        },
      ]);
    });

    it("should detect FreeMarker SSTI with ${8*8} payload", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/process",
        body: "param=value",
        headers: {
          "Content-Type": ["application/x-www-form-urlencoded"],
        },
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "Processing value", // Parameter reflected
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "POST",
          path: "/process",
          body: "param=value${8*8}",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: {
            "Content-Type": ["text/html"],
          },
          body: "Processing value64", // ${8*8} evaluated to 64
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.MEDIUM } },
      );

      // Find the step that contains findings
      const stepWithFindings = executionHistory[0]?.steps?.find(step => 
        step.findings && step.findings.length > 0
      );
      
      expect(stepWithFindings?.findings?.[0]).toMatchObject({
        name: "Server-Side Template Injection in parameter 'param'",
        severity: "critical",
      });
    });

    it("should detect ERB SSTI with <%= 7*7 %> payload", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/view",
        query: "input=data",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "Input: data",
      });

      let callCount = 0;
      const sendHandler = () => {
        callCount++;
        const mockRequest = createMockRequest({
          id: `${callCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/view",
          query: callCount <= 4 ? `input=data{{7*7}}` : `input=data<%= 7*7 %>`,
        });

        const mockResponse = createMockResponse({
          id: `${callCount + 1}`,
          code: 200,
          headers: {
            "Content-Type": ["text/html"],
          },
          body: callCount <= 4 ? "Input: data{{7*7}}" : "Input: data49", // Only ERB evaluates
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.MEDIUM } },
      );

      // Find the step that contains findings
      const stepWithFindings = executionHistory[0]?.steps?.find(step => 
        step.findings && step.findings.length > 0
      );
      expect(stepWithFindings?.findings?.[0]?.description).toContain("ERB");
    });
  });

  describe("Template Error Detection", () => {
    it("should detect SSTI through Jinja2 template errors", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/template",
        query: "name=test",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "Welcome test",
      });

      let callCount = 0;
      const sendHandler = () => {
        callCount++;
        const mockRequest = createMockRequest({
          id: `${callCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/template",
          query: callCount <= 2 ? `name=test{{7*7}}` : `name=test{{7*'7'}}`,
        });

        const mockResponse = createMockResponse({
          id: `${callCount + 1}`,
          code: 500,
          headers: {
            "Content-Type": ["text/html"],
          },
          body: callCount <= 2 
            ? "Welcome test{{7*7}}" // No evaluation for first payloads
            : "jinja2.exceptions.TemplateSyntaxError: unexpected character", // Template error
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.MEDIUM } },
      );

      const errorFinding = executionHistory[0]?.steps?.find(step => 
        step.stepName === "testErrorPayloads"
      )?.findings?.[0];

      expect(errorFinding).toMatchObject({
        name: "Potential Server-Side Template Injection in parameter 'name'",
        severity: "high",
      });
      expect(errorFinding?.description).toContain("jinja2.exceptions.TemplateSyntaxError");
    });

    it("should detect SSTI through Twig template errors", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "data=input",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "Data: input",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/page",
          query: "data=input{{7*'7'}}",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 500,
          body: "Twig_Error_Syntax: Unexpected character",
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      const errorStep = executionHistory[0]?.steps?.find(step => 
        step.stepName === "testErrorPayloads"
      );
      expect(errorStep?.findings?.[0]?.description).toContain("Twig_Error_Syntax");
    });
  });

  describe("Context Access Detection", () => {
    it("should detect template context access", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/info",
        query: "test=value",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "Test: value",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/info",
          query: "test=value{{request}}",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          body: "Test: Request object information here",
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.MEDIUM } },
      );

      const contextStep = executionHistory[0]?.steps?.find(step => 
        step.stepName === "testContextPayloads"
      );
      expect(contextStep?.findings?.[0]).toMatchObject({
        name: "Possible Server-Side Template Injection in parameter 'test'",
        severity: "medium",
      });
    });
  });

  describe("Aggressivity Scaling", () => {
    it("should use fewer payloads on LOW aggressivity", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=test",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "Value: test",
      });

      let sendCallCount = 0;
      const sendHandler = () => {
        sendCallCount++;
        const mockRequest = createMockRequest({
          id: `${sendCallCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/test",
          query: `param=test{{${sendCallCount + 6}*${sendCallCount + 6}}}`,
        });

        const mockResponse = createMockResponse({
          id: `${sendCallCount + 1}`,
          code: 200,
          body: `Value: test{{${sendCallCount + 6}*${sendCallCount + 6}}}`, // No evaluation
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      // LOW aggressivity should test only 2 mathematical payloads + 1 error payload
      expect(sendCallCount).toBeLessThanOrEqual(3);
    });

    it("should use more payloads on HIGH aggressivity", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=test",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "Value: test",
      });

      let sendCallCount = 0;
      const sendHandler = () => {
        sendCallCount++;
        const mockRequest = createMockRequest({
          id: `${sendCallCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/test",
          query: `param=test{{${sendCallCount + 6}*${sendCallCount + 6}}}`,
        });

        const mockResponse = createMockResponse({
          id: `${sendCallCount + 1}`,
          code: 200,
          body: `Value: test{{${sendCallCount + 6}*${sendCallCount + 6}}}`,
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.HIGH } },
      );

      // HIGH aggressivity should test all payloads (10 math + 6 error + 5 context = 21)
      expect(sendCallCount).toBeGreaterThan(10);
    });
  });

  describe("False Positive Prevention", () => {
    it("should not trigger on coincidental numbers in response", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "id=123",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "User ID: 123",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/page",
          query: "id=123{{7*7}}",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          body: "User ID: 49 items found", // Contains 49 but not from template evaluation
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      const mathSteps = executionHistory[0]?.steps?.filter(step => 
        step.stepName === "testMathematicalPayloads"
      );
      // Should not detect SSTI because mathematical expression wasn't properly evaluated
      expect(mathSteps?.some(step => step.findings && step.findings.length > 0)).toBeFalsy();
    });

    it("should only test reflected parameters", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "param=value",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "No reflection here", // Parameter value not reflected
      });

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { 
          sendHandler: () => Promise.reject("Should not send requests"),
          config: { aggressivity: ScanAggressivity.LOW }
        },
      );

      // Should finish after findReflectedParameters step with no findings
      expect(executionHistory).toHaveLength(1);
      expect(executionHistory[0]?.steps).toHaveLength(1);
      expect(executionHistory[0]?.steps?.[0]?.stepName).toBe("findReflectedParameters");
      expect(executionHistory[0]?.steps?.[0]?.result).toBe("done");
    });
  });

  describe("Error Handling", () => {
    it("should handle network errors gracefully", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "test=value",
      });

      const response = createMockResponse({
        id: "1",
        code: 200,
        body: "Test: value",
      });

      const sendHandler = () => {
        return Promise.reject(new Error("Network error"));
      };

      const executionHistory = await runCheck(
        sstiCheck,
        [{ request, response }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      // Should handle error gracefully and continue through all steps
      expect(executionHistory[0]?.status).toBe("completed");
      expect(executionHistory[0]?.steps?.length).toBeGreaterThan(1);
    });
  });
});