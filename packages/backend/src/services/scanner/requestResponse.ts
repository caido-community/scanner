import { type BasicRequest, Result } from "shared";

import { IdSchema } from "../../schemas";
import { requireSDK } from "../../sdk";
import { toBasicRequest, uint8ArrayToString } from "../../utils/request";
import { validateInput } from "../../utils/validation";

export const getRequestResponse = async (
  requestId: string,
): Promise<
  Result<{
    request: BasicRequest & { raw: string };
    response: { id: string; raw: string };
  }>
> => {
  const validation = validateInput(IdSchema, requestId);
  if (validation.kind === "Error") {
    return validation;
  }

  const result = await requireSDK().requests.get(validation.value);
  if (!result) {
    return Result.err("Request not found");
  }

  const { request, response } = result;
  if (!response) {
    return Result.err("Response not found");
  }

  return Result.ok({
    request: {
      ...toBasicRequest(request),
      raw: uint8ArrayToString(request.toSpecRaw().getRaw()),
    },
    response: {
      id: response.getId(),
      raw: response.getRaw().toText(),
    },
  });
};
