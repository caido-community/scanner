import { defineStore } from "pinia";

import { useSelectionState } from "./useSelectionState";
import { useSessionsState } from "./useSessionsState";

export const useScannerStore = defineStore("stores.scanner", () => {
  return {
    ...useSessionsState(),
    ...useSelectionState(),
  };
});
