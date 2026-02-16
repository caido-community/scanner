import {
  createTargetAccessor,
  extractParameters as engineExtractParameters,
  type RuntimeContext,
  type ScanTarget,
} from "engine";

export function extractParameters(context: RuntimeContext) {
  return engineExtractParameters(context.target.request);
}

export function extractReflectedParameters(context: RuntimeContext) {
  const responseBody = context.target.response?.getBody()?.toText();
  return engineExtractParameters(context.target.request, {
    reflected: true,
    responseBody,
  });
}

export function hasParameters(target: ScanTarget): boolean {
  return createTargetAccessor(target).hasParameters();
}
