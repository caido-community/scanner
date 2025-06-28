import { defineStore } from "pinia";

import { useSDK } from "@/plugins/sdk";
import { useScannerRepository } from "@/repositories/scanner";
import { useScannerStore } from "@/stores/scanner";

export const useScannerService = defineStore("services.scanner", () => {
  const sdk = useSDK();
  const store = useScannerStore();
  const repository = useScannerRepository();

  const getState = () => store.getState();

  const initialize = async () => {
    store.send({ type: "Start" });
    const result = await repository.getScanSessions();

    if (result.kind === "Success") {
      store.send({ type: "Success", sessions: result.value });
    } else {
      store.send({ type: "Error", error: result.error });
    }

    sdk.backend.onEvent("session:updated", (_, state) => {
      console.log("session:updated", state);
      store.send({ type: "UpdateSession", session: state });
    });

    sdk.backend.onEvent("session:created", (id, state) => {
      console.log("session:created", state);
      store.send({ type: "AddSession", session: state });
    });
  };

  const startActiveScan = async (requestIDs: string[]) => {
    const result = await repository.startActiveScan(requestIDs);

    if (result.kind === "Success") {
      store.send({ type: "AddSession", session: result.value });
    } else {
      sdk.window.showToast(result.error, {
        variant: "error",
      });
    }
  };

  const selectSession = async (sessionId: string) => {
    store.selectionState.send({ type: "Start", sessionId });
    const result = await repository.getScanSession(sessionId);

    if (result.kind === "Success") {
      store.selectionState.send({
        type: "Success",
        sessionId,
        session: result.value,
      });
    } else {
      store.selectionState.send({
        type: "Error",
        sessionId,
        error: result.error,
      });
    }
  };

  return { getState, initialize, startActiveScan, selectSession };
});
