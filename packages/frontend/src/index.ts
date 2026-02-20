import { Classic } from "@caido/primevue";
import { createPinia } from "pinia";
import PrimeVue from "primevue/config";
import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import "./styles/index.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

import { ScanLauncher } from "@/components/launcher";
import { useConfigService } from "@/services/config";
import { useLauncher } from "@/stores/launcher";
import { getSelectedRequestFromDOM } from "@/utils/utils";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);
  const pinia = createPinia();

  app.use(pinia);

  app.use(PrimeVue, {
    unstyled: true,
    pt: Classic,
  });

  app.use(SDKPlugin, sdk);
  const root = document.createElement("div");
  Object.assign(root.style, {
    height: "100%",
    width: "100%",
  });

  root.id = `plugin--scanner`;

  app.mount(root);

  let sidebarCount = 0;
  sdk.navigation.addPage("/scanner", {
    body: root,
    onEnter: () => {
      const configService = useConfigService();

      configService.refresh();
      sidebarCount = 0;
      sidebarItem.setCount(sidebarCount);
    },
  });

  const sidebarItem = sdk.sidebar.registerItem("Scanner", "/scanner", {
    icon: "fas fa-shield-alt",
  });

  const incrementCount = () => {
    sidebarCount++;
    sidebarItem.setCount(sidebarCount);
  };

  sdk.commands.register("run-active-scanner", {
    name: "Run Active Scanner",
    run: (context) => {
      let requests = [];

      if (context.type === "RequestRowContext") {
        context.requests.forEach((request) => {
          requests.push({
            id: request.id.toString(),
            host: request.host,
            port: request.port,
            path: request.path,
            query: request.query,
          });
        });
      } else if (context.type === "RequestContext") {
        const request = context.request;
        if (request.type === "RequestFull") {
          requests.push({
            id: request.id.toString(),
            host: request.host,
            port: request.port,
            path: request.path,
            query: request.query,
          });
        } else {
          sdk.window.showToast("No requests selected", { variant: "warning" });
          return;
        }
      } else if (context.type === "BaseContext") {
        const request = getSelectedRequestFromDOM();
        if (request !== undefined) {
          requests.push(request);
        } else {
          sdk.window.showToast("No request editor active or selected", {
            variant: "warning",
          });
          return;
        }
      } else {
        sdk.window.showToast("No requests selected", { variant: "warning" });
        return;
      }

      requests = requests.filter(
        (request, index, self) =>
          index ===
          self.findIndex(
            (t) =>
              t.host === request.host &&
              t.port === request.port &&
              t.path === request.path &&
              t.query === request.query,
          ),
      );

      if (requests.length === 0) {
        sdk.window.showToast("No requests selected", { variant: "warning" });
        return;
      }

      const launcherStore = useLauncher();
      launcherStore.restart();
      const targets = requests.map((request) => ({
        ...request,
        method: "GET",
      }));
      launcherStore.form.targets = targets;

      const dialog = sdk.window.showDialog(
        {
          component: ScanLauncher,
          props: {
            sdk,
            incrementCount: () => incrementCount, // we can't just do incrementCount because it auto-executes it when creating dialog
          },
        },
        {
          title: "Scan Launcher",
          draggable: false,
          closeOnEscape: true,
          modal: true,
          position: "center",
        },
      );
      launcherStore.setDialog(dialog);
    },
    group: "Scanner",
    when: (context) => {
      if (context.type === "RequestRowContext") {
        return true;
      }
      if (context.type === "RequestContext") {
        return context.request.type === "RequestFull";
      }
      if (context.type === "BaseContext") {
        return true;
      }
      return false;
    },
  });

  sdk.shortcuts.register("run-active-scanner", ["Control", "Shift", "S"]);

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "run-active-scanner",
    leadingIcon: "fas fa-shield-alt",
  });

  sdk.menu.registerItem({
    type: "Request",
    commandId: "run-active-scanner",
    leadingIcon: "fas fa-shield-alt",
  });
};
