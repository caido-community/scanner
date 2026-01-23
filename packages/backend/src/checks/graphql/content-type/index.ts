import { continueWith, defineCheck, done, Severity } from "engine";
import { z } from "zod";

import { Tags } from "../../../types";
import { keyStrategy } from "../../../utils/key";

const SIMPLE_CONTENT_TYPES = [
  {
    contentType: "application/x-www-form-urlencoded",
    name: "application/x-www-form-urlencoded",
  },
];

const GraphQLResponseSchema = z.object({
  data: z.unknown().optional(),
  errors: z.array(z.unknown()).optional(),
});

const GraphQLRequestSchema = z
  .object({
    operationName: z.union([z.string(), z.null()]).optional(),
    query: z.string().optional(),
    variables: z.unknown().optional(),
  })
  .refine(
    (data) => data.query !== undefined || data.operationName !== undefined,
    {
      message: "GraphQL request must have either query or operationName",
    },
  );

function isSuccessfulGraphQLResponse(body: string): boolean {
  try {
    const parsed: unknown = JSON.parse(body);
    const result = GraphQLResponseSchema.safeParse(parsed);
    return result.success && result.data.data !== undefined;
  } catch {
    return false;
  }
}

function isGraphQLRequest(body: string): boolean {
  try {
    const parsed: unknown = JSON.parse(body);
    return GraphQLRequestSchema.safeParse(parsed).success;
  } catch {
    return false;
  }
}

type State = {
  contentTypesToTest: Array<{ contentType: string; name: string }>;
};

export default defineCheck<State>(({ step }) => {
  step("init", (state, context) => {
    const method = context.target.request.getMethod().toUpperCase();
    if (method !== "POST") {
      return done({ state });
    }

    const originalBody = context.target.request.getBody()?.toText();
    if (
      originalBody === undefined ||
      originalBody === "" ||
      !isGraphQLRequest(originalBody)
    ) {
      return done({ state });
    }

    const originalContentType = context.target.request
      .getHeader("content-type")?.[0]
      ?.toLowerCase();

    const contentTypesToTest = SIMPLE_CONTENT_TYPES.filter(
      (ct) =>
        originalContentType === undefined ||
        !originalContentType.includes(ct.contentType),
    );

    if (contentTypesToTest.length === 0) {
      return done({ state });
    }

    return continueWith({
      nextStep: "testContentType",
      state: { contentTypesToTest },
    });
  });

  step("testContentType", async (state, context) => {
    const [currentTest, ...remainingTests] = state.contentTypesToTest;

    if (currentTest === undefined) {
      return done({ state });
    }

    const spec = context.target.request.toSpec();
    spec.setHeader("Content-Type", currentTest.contentType);

    const { request, response } = await context.sdk.requests.send(spec);

    if (response !== undefined) {
      const responseBody = response.getBody()?.toText();
      const responseCode = response.getCode();

      if (
        responseCode >= 200 &&
        responseCode < 300 &&
        responseBody !== undefined &&
        isSuccessfulGraphQLResponse(responseBody)
      ) {
        return done({
          state: { contentTypesToTest: remainingTests },
          findings: [
            {
              name: `GraphQL Content-Type Not Validated (${currentTest.name})`,
              description: `The GraphQL endpoint accepts requests with \`${currentTest.contentType}\` Content-Type header and returns a valid GraphQL response.\n\nCross-site request forgery (CSRF) vulnerabilities in a GraphQL endpoint can arise when the content type is not validated. POST requests using a content-type of \`application/json\` are secure against forgery as long as the content type is validated, as an attacker wouldn't be able to make the victim's browser send this request.\n\nHowever, requests that have a content-type of \`x-www-form-urlencoded\` can be sent by a browser and so may leave users vulnerable to attack. Where this is the case, attackers may be able to craft exploits that use a valid CSRF token from a previous request to send malicious requests to the API.\n\n**Recommendation:**\nConfigure the GraphQL server to only accept \`application/json\` Content-Type for GraphQL requests and reject any other content types.`,
              severity: Severity.MEDIUM,
              correlation: {
                requestID: request.getId(),
                locations: [],
              },
            },
          ],
        });
      }
    }

    if (remainingTests.length === 0) {
      return done({ state: { contentTypesToTest: [] } });
    }

    return continueWith({
      nextStep: "testContentType",
      state: { contentTypesToTest: remainingTests },
    });
  });

  return {
    metadata: {
      id: "graphql-content-type",
      name: "GraphQL Content-Type Not Validated",
      description:
        "Detects GraphQL endpoints that accept x-www-form-urlencoded content type, making them vulnerable to CSRF attacks",
      type: "active",
      tags: [Tags.GRAPHQL, Tags.CSRF],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 1, maxRequests: 1 },
      dependsOn: ["graphql-endpoint"],
    },
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    initState: () => ({ contentTypesToTest: [] }),
    when: () => true,
  };
});
