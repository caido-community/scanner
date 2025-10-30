import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const SERIALIZED_CONTENT_TYPES = [
  "application/x-java-serialized-object",
  "application/x-java-serialized-object;charset=",
];

const SERIALIZED_BODY_SIGNATURES = ["rO0AB", "aced0005"];

const hasSerializedContentType = (headers: Array<string> | undefined) => {
  if (headers === undefined || headers.length === 0) {
    return false;
  }

  return headers.some((header) => {
    const lowerHeader = header.toLowerCase();
    return SERIALIZED_CONTENT_TYPES.some((type) =>
      lowerHeader.includes(type.toLowerCase()),
    );
  });
};

const hasSerializedSignature = (body: string | undefined) => {
  if (body === undefined || body.length === 0) {
    return false;
  }

  return SERIALIZED_BODY_SIGNATURES.some((signature) =>
    body.includes(signature),
  );
};

export default defineCheck(({ step }) => {
  step("detectSerializedObjects", (state, context) => {
    const { request, response } = context.target;
    const findings = [];

    const requestBodyText = request.getBody()?.toText() ?? "";
    const responseBodyText = response?.getBody()?.toText() ?? "";

    const requestBody = requestBodyText.slice(0, 5000); // limit to avoid large strings
    const responseBody = responseBodyText.slice(0, 5000);

    const requestSerialized =
      hasSerializedContentType(request.getHeader("content-type")) ||
      hasSerializedSignature(requestBody);

    if (requestSerialized) {
      findings.push({
        name: "Serialized object detected in HTTP request",
        description:
          "The request appears to include a Java serialized object. Accepting serialized objects over HTTP can lead to remote code execution if deserialization occurs without strict validation.",
        severity: Severity.HIGH,
        correlation: {
          requestID: request.getId(),
          locations: [],
        },
      });
    }

    if (response !== undefined) {
      const responseSerialized =
        hasSerializedContentType(response.getHeader("content-type")) ||
        hasSerializedSignature(responseBody);

      if (responseSerialized) {
        findings.push({
          name: "Serialized object detected in HTTP response",
          description:
            "The response body appears to contain a Java serialized object. Serving serialized objects over HTTP may expose deserialization gadgets to attackers and should be avoided.",
          severity: Severity.MEDIUM,
          correlation: {
            requestID: request.getId(),
            locations: [],
          },
        });
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "serialized-object-http-message",
      name: "Serialized Object in HTTP message",
      description:
        "Detects Java serialized objects transmitted in HTTP requests or responses",
      type: "passive",
      tags: [Tags.SERIALIZATION, Tags.INPUT_VALIDATION, Tags.SENSITIVE_DATA],
      severities: [Severity.HIGH, Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy()
      .withHost()
      .withPort()
      .withPath()
      .withMethod()
      .build(),
    when: () => true,
  };
});
