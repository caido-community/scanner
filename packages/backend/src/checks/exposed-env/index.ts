import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const ENV_FILES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".env.staging",
  ".env.test",
  ".env.backup",
  ".env.old",
  ".env.bak",
  ".env.dev",
  ".env.prod",
  ".env.stage",
  ".env.live",
];

const getEnvFilesToTest = (aggressivity: ScanAggressivity): string[] => {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return ENV_FILES.slice(0, 1);
    case ScanAggressivity.MEDIUM:
      return ENV_FILES.slice(0, 4);
    case ScanAggressivity.HIGH:
      return ENV_FILES;
    default:
      return ENV_FILES.slice(0, 1);
  }
};

const getBasePath = (originalPath: string): string => {
  return originalPath.split("/").slice(0, -1).join("/");
};

const isValidEnvContent = (bodyText: string, contentType: string): boolean => {
  const normalizedContentType = contentType.toLowerCase().split(";")[0]?.trim();

  if (bodyText.length > 500) {
    return false;
  }

  if (
    normalizedContentType !== undefined &&
    normalizedContentType !== "application/octet-stream" &&
    !normalizedContentType.startsWith("text/")
  ) {
    return false;
  }

  const trimmedBody = bodyText.trim();
  if (!trimmedBody) {
    return false;
  }

  if (trimmedBody.includes("<html")) {
    return false;
  }

  const commentPattern = /^#\s{0,10}\w+/m;
  const keyValuePattern = /^\w+=\w+/m;
  const envKeyPattern =
    /^[a-z_]*(KEY|TOKEN|PASS|SECRET|DB_URL|DATABASE_URL|MAILER_URL|APP_|DB_)[a-z_]*=/im;

  const hasComments = commentPattern.test(trimmedBody);
  const hasKeyValue = keyValuePattern.test(trimmedBody);
  const hasEnvKeys = envKeyPattern.test(trimmedBody);

  if (normalizedContentType === "application/octet-stream") {
    return (hasComments || hasKeyValue) && hasEnvKeys;
  }

  return hasEnvKeys;
};

export default defineCheck<{
  envFiles: string[];
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const envFiles = getEnvFilesToTest(context.config.aggressivity);
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testEnvFile",
      state: { envFiles, basePath },
    });
  });

  step("testEnvFile", async (state, context) => {
    // If there are no more files to test, we're done
    if (state.envFiles.length === 0) {
      return done({
        state,
      });
    }

    const [currentFile, ...remainingFiles] = state.envFiles;
    if (currentFile === undefined) {
      return done({
        state,
      });
    }

    const envPath = state.basePath + "/" + currentFile;
    const request = context.target.request.toSpec();

    request.setPath(envPath);
    request.setMethod("GET");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body) {
        const bodyText = body.toText();
        const contentType =
          result.response.getHeader("content-type")?.[0] ?? "";

        if (isValidEnvContent(bodyText, contentType)) {
          return continueWith({
            nextStep: "testEnvFile",
            state: {
              ...state,
              envFiles: remainingFiles,
            },
            findings: [
              {
                name: "Exposed Environment File",
                description: `Environment file is publicly accessible at \`${envPath}\`. This file may contain sensitive configuration data, API keys, or credentials.`,
                severity: Severity.CRITICAL,
                correlation: {
                  requestID: result.request.getId(),
                  locations: [],
                },
              },
            ],
          });
        }
      }
    }

    // Move on to the next file
    return continueWith({
      nextStep: "testEnvFile",
      state: {
        ...state,
        envFiles: remainingFiles,
      },
    });
  });

  return {
    metadata: {
      id: "exposed-env",
      name: "Exposed Environment File",
      description:
        "Detects publicly accessible environment files (.env, .env.local, etc.) that may contain sensitive configuration data",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 1,
        maxRequests: ENV_FILES.length,
      },
    },

    initState: () => ({ envFiles: [], basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
