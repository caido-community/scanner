import { Buffer } from "buffer";

import { type ExecutionHistory } from "engine";

export const packExecutionHistory = (history: ExecutionHistory): string => {
  const json = JSON.stringify(history);
  return Buffer.from(json, "utf-8").toString("base64");
};
