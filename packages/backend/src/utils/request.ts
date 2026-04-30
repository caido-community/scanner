import type { BasicRequest } from "shared";

export const toBasicRequest = (request: {
  getId: () => string;
  getHost: () => string;
  getPort: () => number;
  getPath: () => string;
  getQuery: () => string;
  getMethod: () => string;
}): BasicRequest => ({
  id: request.getId(),
  host: request.getHost(),
  port: request.getPort(),
  path: request.getPath(),
  query: request.getQuery(),
  method: request.getMethod().toUpperCase(),
});

export const uint8ArrayToString = (data: Uint8Array): string => {
  let output = "";
  const chunkSize = 256;
  for (let i = 0; i < data.length; i += chunkSize) {
    output += String.fromCharCode(...data.subarray(i, i + chunkSize));
  }
  return output;
};
