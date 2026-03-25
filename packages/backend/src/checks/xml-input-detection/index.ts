import { defineCheckV2, Result, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const XML_BODY = '<?xml version="1.0"?><test>1</test>';

export default defineCheckV2({
  id: "xml-input-detection",
  name: "XML Input Accepted",
  description:
    "Detects endpoints that accept and parse XML input, which may be vulnerable to XXE or other XML-based attacks",
  type: "active",
  tags: [Tags.XXE, Tags.INFORMATION_DISCLOSURE],
  severities: [Severity.INFO],
  aggressivity: {
    minRequests: 2,
    maxRequests: 2,
  },
  minAggressivity: "medium",
  dedupeKey: keyStrategy()
    .withMethod()
    .withHost()
    .withPort()
    .withPath()
    .build(),
  when: (target) => {
    const method = target.request.getMethod().toUpperCase();
    return method === "POST" || method === "PUT" || method === "PATCH";
  },

  async execute(ctx) {
    const xmlSpec = ctx.target.request.toSpec();
    xmlSpec.setHeader("Content-Type", "application/xml");
    xmlSpec.setBody(XML_BODY);
    xmlSpec.setQuery("");

    const xmlResult = await ctx.send(xmlSpec);
    if (Result.isErr(xmlResult)) return;

    const xmlCode = xmlResult.value.response.getCode();

    const controlSpec = ctx.target.request.toSpec();
    controlSpec.setHeader("Content-Type", "application/zml");
    controlSpec.setBody(XML_BODY);
    controlSpec.setQuery("");

    const controlResult = await ctx.send(controlSpec);
    if (Result.isErr(controlResult)) return;

    const controlCode = controlResult.value.response.getCode();

    const xmlBody = xmlResult.value.response.getBody()?.toText() ?? "";
    const hasXmlIndicator =
      xmlBody.includes("<?xml") ||
      xmlBody.includes("SAXParseException") ||
      xmlBody.includes("XMLSyntaxError") ||
      xmlBody.includes("lxml.etree") ||
      xmlBody.includes("XML parsing error") ||
      xmlBody.includes("simplexml_load") ||
      /^<[a-zA-Z]/.test(xmlBody.trim());

    const codesDiffer = xmlCode !== controlCode;

    if (!codesDiffer && !hasXmlIndicator) return;

    const evidence: string[] = [];
    if (codesDiffer)
      evidence.push(
        `status codes differ (xml: ${xmlCode}, control: ${controlCode})`,
      );
    if (hasXmlIndicator) evidence.push("XML-specific content in response body");

    ctx.finding({
      name: "XML Input Accepted",
      description: `The endpoint appears to accept and parse XML input. Evidence: ${evidence.join("; ")}.\n\nEndpoints that parse XML may be vulnerable to XML External Entity (XXE) injection, XML bomb denial-of-service, or other XML-specific attacks.`,
      severity: Severity.INFO,
      request: xmlResult.value.request,
      impact:
        "If the XML parser is not properly configured, attackers may exploit XXE vulnerabilities to read local files, perform SSRF, or cause denial of service.",
      recommendation:
        "Ensure XML parsers disable external entity processing. Use `FEATURE_SECURE_PROCESSING` in Java, or `libxml_disable_entity_loader()` in PHP. Consider using JSON instead of XML where possible.",
    });
  },
});
