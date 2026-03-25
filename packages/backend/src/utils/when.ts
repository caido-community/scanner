import { type ScanTarget } from "engine";

export function whenTextResponse(target: ScanTarget): boolean {
  if (target.response === undefined) return false;
  const code = target.response.getCode();
  if (code < 200 || code >= 300) return false;
  const ct = target.response.getHeader("content-type")?.[0] ?? "";
  if (/image|font|audio|video|octet-stream/i.test(ct)) return false;
  const body = target.response.getBody();
  if (body === undefined) return false;
  return body.toText().length <= 500_000;
}
