import type { BackendSDK } from "./types";

let sdk: BackendSDK | undefined;

export const setSDK = (_sdk: BackendSDK): void => {
  sdk = _sdk;
};

export const requireSDK = (): BackendSDK => {
  if (sdk === undefined) {
    throw new Error("Scanner SDK not initialized");
  }
  return sdk;
};
