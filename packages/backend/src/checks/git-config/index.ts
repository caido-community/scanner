import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
  type Severity as SeverityType,
} from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const GIT_FILES = [
  ".git/config",
  ".git/logs/HEAD",
  ".git/HEAD",
  ".git/index",
  ".git/logs/refs/heads/master",
  ".git/logs/refs/heads/main",
];

const getGitFilesToTest = (aggressivity: ScanAggressivity): string[] => {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return GIT_FILES.slice(0, 1);
    case ScanAggressivity.MEDIUM:
      return GIT_FILES.slice(0, 3);
    case ScanAggressivity.HIGH:
      return GIT_FILES;
    default:
      return GIT_FILES.slice(0, 2);
  }
};

const getBasePath = (originalPath: string): string => {
  return originalPath.split("/").slice(0, -1).join("/");
};

const isValidGitConfig = (bodyText: string): boolean => {
  const trimmedBody = bodyText.trim();
  if (!trimmedBody) {
    return false;
  }

  const configSections = ["[credentials]", "[core]", "[remote", "[branch"];
  return configSections.some((section) => trimmedBody.includes(section));
};

const isValidGitLogs = (bodyText: string): boolean => {
  const trimmedBody = bodyText.trim();
  if (!trimmedBody) {
    return false;
  }

  const gitLogPattern = /^[a-f0-9]{40}\s+[a-f0-9]{40}\s+/m;
  return gitLogPattern.test(trimmedBody);
};

const isValidGitContent = (bodyText: string, contentType: string): boolean => {
  const normalizedContentType = contentType.toLowerCase().split(";")[0]?.trim();

  if (normalizedContentType !== undefined) {
    if (
      normalizedContentType.startsWith("text/html") ||
      normalizedContentType.startsWith("text/xml") ||
      normalizedContentType.startsWith("image/") ||
      normalizedContentType.startsWith("video/") ||
      normalizedContentType.startsWith("audio/") ||
      normalizedContentType.startsWith("application/octet-stream") ||
      normalizedContentType.startsWith("application/pdf") ||
      normalizedContentType.includes("json") ||
      normalizedContentType.includes("javascript")
    ) {
      return false;
    }
  }

  const bodyLower = bodyText.toLowerCase();
  if (
    bodyLower.includes("<html") ||
    bodyLower.includes("<body") ||
    bodyLower.includes("<!doctype") ||
    bodyLower.includes("{") ||
    bodyLower.includes("}")
  ) {
    return false;
  }

  return true;
};

const getGitFileType = (filePath: string): "config" | "logs" | "other" => {
  if (filePath.includes("/config")) {
    return "config";
  }
  if (filePath.includes("/logs/")) {
    return "logs";
  }
  return "other";
};

const validateGitFile = (
  bodyText: string,
  contentType: string,
  filePath: string,
): boolean => {
  if (!isValidGitContent(bodyText, contentType)) {
    return false;
  }

  const fileType = getGitFileType(filePath);

  switch (fileType) {
    case "config":
      return isValidGitConfig(bodyText);
    case "logs":
      return isValidGitLogs(bodyText);
    default:
      return bodyText.trim().length > 0;
  }
};

export default defineCheck<{
  gitFiles: string[];
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const gitFiles = getGitFilesToTest(context.config.aggressivity);
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testGitFile",
      state: { gitFiles, basePath },
    });
  });

  step("testGitFile", async (state, context) => {
    if (state.gitFiles.length === 0) {
      return done({
        state,
      });
    }

    const [currentFile, ...remainingFiles] = state.gitFiles;
    if (currentFile === undefined) {
      return done({
        state,
      });
    }

    const gitPath = state.basePath + "/" + currentFile;
    const request = context.target.request.toSpec();

    request.setPath(gitPath);
    request.setMethod("GET");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body) {
        const bodyText = body.toText();
        const contentType =
          result.response.getHeader("content-type")?.[0] ?? "";

        if (validateGitFile(bodyText, contentType, currentFile)) {
          const fileType = getGitFileType(currentFile);
          let severity: SeverityType = Severity.MEDIUM;
          let description = `Git file is publicly accessible at \`${gitPath}\`. This may expose sensitive repository information.`;

          if (fileType === "config") {
            severity = Severity.CRITICAL;
            description = `Git configuration file is publicly accessible at \`${gitPath}\`. This file may contain sensitive information such as credentials, repository URLs, and configuration settings.`;
          } else if (fileType === "logs") {
            description = `Git log file is publicly accessible at \`${gitPath}\`. This file may expose commit history, author information, and development patterns.`;
          }

          return done({
            findings: [
              {
                name: "Exposed Git File",
                description,
                severity,
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
      nextStep: "testGitFile",
      state: {
        ...state,
        gitFiles: remainingFiles,
      },
    });
  });

  return {
    metadata: {
      id: "git-config",
      name: "Exposed Git Files",
      description:
        "Detects publicly accessible Git files (.git/config, .git/logs/HEAD, etc.) that may contain sensitive repository information",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM, Severity.CRITICAL],
      aggressivity: {
        minRequests: 2,
        maxRequests: GIT_FILES.length,
      },
    },

    initState: () => ({ gitFiles: [], basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
