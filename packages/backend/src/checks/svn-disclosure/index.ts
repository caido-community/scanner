import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { getBasePath, keyStrategy } from "../../utils/key";

const SVN_FILES = [".svn/entries", ".svn/wc.db"];

const getSvnFilesToTest = (aggressivity: ScanAggressivity): string[] => {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return SVN_FILES.slice(0, 1);
    case ScanAggressivity.MEDIUM:
    case ScanAggressivity.HIGH:
      return SVN_FILES;
    default:
      return SVN_FILES.slice(0, 1);
  }
};

const isValidSvnEntries = (bodyText: string): boolean => {
  const firstLine = bodyText.trim().split("\n")[0]?.trim();
  if (firstLine === undefined) return false;
  return ["8", "9", "10", "12"].includes(firstLine);
};

const isValidSvnWcDb = (bodyText: string): boolean => {
  return bodyText.startsWith("SQLite format 3");
};

export default defineCheck<{
  svnFiles: string[];
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const svnFiles = getSvnFilesToTest(context.config.aggressivity);
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testSvnFile",
      state: { svnFiles, basePath },
    });
  });

  step("testSvnFile", async (state, context) => {
    if (state.svnFiles.length === 0) {
      return done({
        state,
      });
    }

    const [currentFile, ...remainingFiles] = state.svnFiles;
    if (currentFile === undefined) {
      return done({
        state,
      });
    }

    const svnPath = state.basePath + "/" + currentFile;
    const request = context.target.request.toSpec();

    request.setPath(svnPath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body !== undefined) {
        const bodyText = body.toText();
        const isEntries = currentFile.endsWith("entries");
        const isValid = isEntries
          ? isValidSvnEntries(bodyText)
          : isValidSvnWcDb(bodyText);

        if (isValid) {
          return continueWith({
            nextStep: "testSvnFile",
            state: {
              ...state,
              svnFiles: remainingFiles,
            },
            findings: [
              {
                name: "SVN Repository Disclosed",
                description: `SVN metadata file is publicly accessible at \`${svnPath}\`. This may expose source code, file paths, and repository history.`,
                severity: Severity.MEDIUM,
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

    return continueWith({
      nextStep: "testSvnFile",
      state: {
        ...state,
        svnFiles: remainingFiles,
      },
    });
  });

  return {
    metadata: {
      id: "svn-disclosure",
      name: "SVN Repository Disclosed",
      description:
        "Detects publicly accessible SVN metadata files that may expose source code and repository information",
      type: "active",
      tags: [Tags.INFRASTRUCTURE, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 1,
        maxRequests: SVN_FILES.length,
      },
    },

    initState: () => ({ svnFiles: [], basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
