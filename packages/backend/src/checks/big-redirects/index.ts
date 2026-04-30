import {
  defineCheck,
  done,
  type RuntimeContext,
  type ScanTarget,
  Severity,
  type StepAction,
} from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const isRedirectResponse = (statusCode: number): boolean => {
  return statusCode >= 300 && statusCode < 400 && statusCode !== 304;
};

const getPredictedResponseSize = (redirectUriLength: number): number => {
  return redirectUriLength + 300;
};

const countHrefOccurrences = (body: string): number => {
  const hrefPattern = /href/gi;
  const matches = body.match(hrefPattern);
  return matches ? matches.length : 0;
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("analyzeRedirect", ((state, context: RuntimeContext) => {
    const response = context.target.response;
    if (!response) {
      return done({ state });
    }

    const statusCode = response.getCode();
    if (!isRedirectResponse(statusCode)) {
      return done({ state });
    }

    const locationHeader = response.getHeader("location");
    const locationValue = locationHeader?.[0];

    if (locationValue === undefined || locationValue === "") {
      return done({ state });
    }

    const responseBody = response.getBody()?.toText() ?? "";
    const responseBodyLength = responseBody.length;
    const locationUriLength = locationValue.length;
    const predictedSize = getPredictedResponseSize(locationUriLength);

    const findings = [];

    // Check for oversized redirect response
    if (responseBodyLength > predictedSize) {
      findings.push({
        name: "Big Redirects - Oversized Response",
        description: `The redirect response is larger than expected. The Location header URI length is ${locationUriLength} characters, which should result in a response body of approximately ${predictedSize} bytes. However, the actual response body is ${responseBodyLength} bytes, which is ${
          responseBodyLength - predictedSize
        } bytes larger than expected. This could indicate that sensitive information is being leaked in the redirect response.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for multiple href links in redirect response
    const hrefCount = countHrefOccurrences(responseBody);
    if (hrefCount > 1) {
      findings.push({
        name: "Big Redirects - Multiple Href Links",
        description: `The redirect response contains ${hrefCount} href links, which is unusual for a redirect response. This could indicate that the response contains additional content that should not be present in a redirect response.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    return done({
      state,
      findings,
    });
  }) as StepAction<Record<never, never>>);

  return {
    metadata: {
      id: "big-redirects",
      name: "Big Redirects",
      description:
        "Detects redirect responses that are larger than expected or contain multiple href links, which could indicate information leakage or improper redirect implementation.",
      type: "passive",
      tags: [Tags.REDIRECT, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQuery()
      .build(),
    when: (target: ScanTarget) => {
      return (
        target.response !== undefined &&
        isRedirectResponse(target.response.getCode())
      );
    },
  };
});
