import { type Dialog } from "@caido/sdk-frontend/src/types/types/window";
import { ScanAggressivity, type ScanConfig, Severity } from "engine";
import { defineStore } from "pinia";
import { type BasicRequest, type ScanRequestPayload } from "shared";
import { reactive, ref } from "vue";

import { useScannerService } from "@/services/scanner";
import { useConfigStore } from "@/stores/config";
import { type FrontendSDK } from "@/types";

type FormState = {
  targets: BasicRequest[];
  config: ScanConfig;
  title: string;
};

const DEFAULT_REQUEST_TIMEOUT = 2 * 60;

export const useLauncher = defineStore("stores.launcher", () => {
  const scannerService = useScannerService();
  const configStore = useConfigStore();
  const defaultFormState: FormState = {
    targets: [],
    config: {
      aggressivity: ScanAggressivity.MEDIUM,
      scopeIDs: [],
      scanTimeout: 10 * 60,
      checkTimeout: 2 * 60,
      requestTimeout: DEFAULT_REQUEST_TIMEOUT,
      concurrentChecks: 2,
      concurrentTargets: 2,
      concurrentRequests: 5,
      severities: [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
      ],
      requestsDelayMs: 50,
    },
    title: "Active Scan",
  };

  const isLoading = ref(false);

  const dialog = ref<Dialog | undefined>(undefined);

  const form = reactive<FormState>({ ...defaultFormState });

  const toRequestPayload = (): ScanRequestPayload => ({
    requestIDs: form.targets.map((target) => target.id),
    scanConfig: form.config,
    title: form.title,
  });

  const onSubmit = async (sdk: FrontendSDK, incrementCount: () => void) => {
    const payload = toRequestPayload();
    isLoading.value = true;
    const result = await scannerService.startActiveScan(payload);

    switch (result.kind) {
      case "Ok": {
        scannerService.selectSession(result.value.id);
        incrementCount();

        dialog.value?.close();
        isLoading.value = false;
        break;
      }
      case "Error":
        isLoading.value = false;
        break;
    }
  };

  const restart = () => {
    Object.assign(form, defaultFormState);
    const configState = configStore.getState();
    if (
      configState.type === "Success" &&
      configState.config.requestTimeout !== undefined
    ) {
      form.config.requestTimeout = configState.config.requestTimeout;
    }
    isLoading.value = false;
  };

  const setDialog = (newDialog: Dialog) => {
    dialog.value = newDialog;
  };

  return {
    form,
    isLoading,
    dialog,
    onSubmit,
    restart,
    setDialog,
  };
});
