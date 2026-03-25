import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { getBasePath, keyStrategy } from "../../utils/key";

const WEB_CONFIG_FILES = ["web.config", "Web.config"];

const getWebConfigFilesToTest = (aggressivity: ScanAggressivity): string[] => {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return WEB_CONFIG_FILES.slice(0, 1);
    case ScanAggressivity.MEDIUM:
    case ScanAggressivity.HIGH:
      return WEB_CONFIG_FILES;
    default:
      return WEB_CONFIG_FILES.slice(0, 1);
  }
};

const isValidWebConfig = (bodyText: string): boolean => {
  if (!bodyText.includes("<configuration")) {
    return false;
  }

  return bodyText.includes("<system.web") || bodyText.includes("<appSettings");
};

export default defineCheck<{
  configFiles: string[];
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const configFiles = getWebConfigFilesToTest(context.config.aggressivity);
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testWebConfig",
      state: { configFiles, basePath },
    });
  });

  step("testWebConfig", async (state, context) => {
    if (state.configFiles.length === 0) {
      return done({
        state,
      });
    }

    const [currentFile, ...remainingFiles] = state.configFiles;
    if (currentFile === undefined) {
      return done({
        state,
      });
    }

    const configPath = state.basePath + "/" + currentFile;
    const request = context.target.request.toSpec();

    request.setPath(configPath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body !== undefined) {
        const bodyText = body.toText();

        if (isValidWebConfig(bodyText)) {
          return done({
            findings: [
              {
                name: "Web.config File Disclosed",
                description: `A \`web.config\` file is publicly accessible at \`${configPath}\`. This file may contain sensitive configuration data such as connection strings, authentication settings, and application secrets.`,
                severity: Severity.HIGH,
                correlation: {
                  requestID: result.request.getId(),
                  locations: [],
                },
              },
            ],
            state,
          });
        }
      }
    }

    return continueWith({
      nextStep: "testWebConfig",
      state: {
        ...state,
        configFiles: remainingFiles,
      },
    });
  });

  return {
    metadata: {
      id: "web-config-disclosure",
      name: "Web.config File Disclosed",
      description:
        "Detects publicly accessible web.config files that may contain sensitive ASP.NET configuration data",
      type: "active",
      tags: [Tags.INFRASTRUCTURE, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: WEB_CONFIG_FILES.length,
      },
    },

    initState: () => ({ configFiles: [], basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
