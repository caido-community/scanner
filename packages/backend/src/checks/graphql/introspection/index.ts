import { defineCheckV2, Result, Severity } from "engine";
import { z } from "zod";

import { Tags } from "../../../types";
import { keyStrategy } from "../../../utils/key";

const INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}';
const GET_INTROSPECTION_QUERY = "query={__schema{types{name}}}";

const IntrospectionSchema = z.object({
  data: z.object({
    __schema: z.object({
      types: z.array(z.unknown()),
    }),
  }),
});

function hasIntrospectionResult(body: string): boolean {
  try {
    return IntrospectionSchema.safeParse(JSON.parse(body)).success;
  } catch {
    return false;
  }
}

export default defineCheckV2({
  id: "graphql-introspection",
  name: "GraphQL Introspection Enabled",
  description:
    "Detects GraphQL endpoints with introspection enabled, which exposes the entire API schema to attackers",
  type: "active",
  tags: [Tags.GRAPHQL, Tags.INFORMATION_DISCLOSURE],
  severities: [Severity.MEDIUM],
  aggressivity: {
    minRequests: 1,
    maxRequests: 2,
  },
  dependsOn: ["graphql-endpoint"],
  dedupeKey: keyStrategy().withHost().withPort().build(),
  when: (target) => {
    const path = target.request.getPath().toLowerCase();
    return path.includes("graphql");
  },

  async execute(ctx) {
    const postSpec = ctx.target.request.toSpec();
    postSpec.setMethod("POST");
    postSpec.setHeader("Content-Type", "application/json");
    postSpec.setBody(INTROSPECTION_QUERY);

    const postResult = await ctx.send(postSpec);
    if (Result.isOk(postResult)) {
      const { request, response } = postResult.value;
      const body = response.getBody()?.toText();

      if (body !== undefined && hasIntrospectionResult(body)) {
        ctx.finding({
          name: "GraphQL Introspection Enabled",
          description:
            "The GraphQL endpoint has introspection enabled, allowing anyone to query the full API schema including all types, fields, queries, mutations, and subscriptions.\n\nIntrospection was confirmed by sending an introspection query via POST and receiving a valid `__schema` response.",
          severity: Severity.MEDIUM,
          request,
          impact:
            "Attackers can enumerate the entire API surface, discover hidden fields, sensitive queries, and internal types that may not be intended for public use.",
          recommendation:
            "Disable introspection in production. In Apollo Server, set `introspection: false`. In other implementations, use middleware to block `__schema` and `__type` queries.",
        });
        return;
      }
    }

    const getSpec = ctx.target.request.toSpec();
    getSpec.setMethod("GET");
    getSpec.setPath(ctx.target.request.getPath());
    getSpec.setQuery(GET_INTROSPECTION_QUERY);
    getSpec.setBody("");

    const getResult = await ctx.send(getSpec);
    if (Result.isErr(getResult)) return;

    const { request: getRequest, response: getResponse } = getResult.value;
    const getBody = getResponse.getBody()?.toText();

    if (getBody !== undefined && hasIntrospectionResult(getBody)) {
      ctx.finding({
        name: "GraphQL Introspection Enabled",
        description:
          "The GraphQL endpoint has introspection enabled, allowing anyone to query the full API schema including all types, fields, queries, mutations, and subscriptions.\n\nIntrospection was confirmed by sending an introspection query via GET and receiving a valid `__schema` response.",
        severity: Severity.MEDIUM,
        request: getRequest,
        impact:
          "Attackers can enumerate the entire API surface, discover hidden fields, sensitive queries, and internal types that may not be intended for public use.",
        recommendation:
          "Disable introspection in production. In Apollo Server, set `introspection: false`. In other implementations, use middleware to block `__schema` and `__type` queries.",
      });
    }
  },
});
