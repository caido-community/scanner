import { type ExecutionHistory } from "engine";
import { Buffer } from "buffer";

export const packExecutionHistory = (history: ExecutionHistory): string => {
  const json = JSON.stringify(history);
  return Buffer.from(json, "utf-8").toString("base64");
};
