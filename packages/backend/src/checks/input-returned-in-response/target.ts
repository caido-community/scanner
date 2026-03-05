import type { ScanTarget } from "engine";

export const hasResponseBody = (target: ScanTarget): boolean => {
  const response = target.response;
  if (response === undefined) {
    return false;
  }

  const body = response.getBody()?.toText();
  return body !== undefined && body !== "";
};
