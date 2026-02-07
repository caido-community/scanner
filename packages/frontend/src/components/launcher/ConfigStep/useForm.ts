import { ScanAggressivity, Severity } from "engine";
import prettyMs from "pretty-ms";
import { computed } from "vue";

import { useSDK } from "@/plugins/sdk";
import { useLauncher } from "@/stores/launcher";

export const useForm = () => {
  const sdk = useSDK();
  const { form } = useLauncher();

  const aggressivityOptions = Object.values(ScanAggressivity).map(
    (aggressivity) => ({
      label: aggressivity.charAt(0).toUpperCase() + aggressivity.slice(1),
      value: aggressivity,
    }),
  );

  const severityOptions = Object.values(Severity).map((severity) => ({
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: severity,
  }));

  const scopeOptions = sdk.scopes.getScopes().map((scope) => ({
    label: scope.name,
    value: scope.id,
  }));

  const readableTimeout = computed(() => {
    const timeout = form.config.scanTimeout;
    if (!timeout || timeout <= 0) {
      return "";
    }
    return prettyMs(timeout * 1000, { verbose: true });
  });

  return {
    form,
    aggressivityOptions,
    severityOptions,
    scopeOptions,
    readableTimeout,
  };
};
