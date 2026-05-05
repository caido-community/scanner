import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const PHPINFO_PATHS = [
  "phpinfo.php",
  "php_info.php",
  "pinfo.php",
  "phpversion.php",
];

const getPhpinfoPathsToTest = (aggressivity: ScanAggressivity): string[] => {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return PHPINFO_PATHS.slice(0, 1);
    case ScanAggressivity.MEDIUM:
      return PHPINFO_PATHS.slice(0, 2);
    case ScanAggressivity.HIGH:
      return PHPINFO_PATHS;
    default:
      return PHPINFO_PATHS.slice(0, 1);
  }
};

const getBasePath = (originalPath: string): string => {
  return originalPath.split("/").slice(0, -1).join("/");
};

const isValidPhpinfoContent = (bodyText: string): boolean => {
  const trimmedBody = bodyText.trim();
  if (!trimmedBody) {
    return false;
  }

  const phpExtensionPattern = /PHP Extension/i;
  const phpVersionPattern = /PHP Version/i;

  return (
    phpExtensionPattern.test(trimmedBody) && phpVersionPattern.test(trimmedBody)
  );
};

export default defineCheck<{
  phpinfoPaths: string[];
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const phpinfoPaths = getPhpinfoPathsToTest(context.config.aggressivity);
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testPhpinfoPath",
      state: { phpinfoPaths, basePath },
    });
  });

  step("testPhpinfoPath", async (state, context) => {
    if (state.phpinfoPaths.length === 0) {
      return done({
        state,
      });
    }

    const [currentPath, ...remainingPaths] = state.phpinfoPaths;
    if (currentPath === undefined) {
      return done({
        state,
      });
    }

    const phpinfoPath = state.basePath + "/" + currentPath;
    const request = context.target.request.toSpec();

    request.setPath(phpinfoPath);
    request.setMethod("GET");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body) {
        const bodyText = body.toText();

        if (isValidPhpinfoContent(bodyText)) {
          return done({
            findings: [
              {
                name: "PHPinfo Page Exposed",
                description: `PHPinfo page is publicly accessible at \`${phpinfoPath}\`. The output of the phpinfo() command can reveal sensitive and detailed PHP environment information including configuration settings, loaded modules, and environment variables.`,
                severity: Severity.LOW,
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
      nextStep: "testPhpinfoPath",
      state: {
        ...state,
        phpinfoPaths: remainingPaths,
      },
    });
  });

  return {
    metadata: {
      id: "phpinfo",
      name: "PHPinfo Page",
      description:
        "Detects publicly accessible PHPinfo pages that may contain sensitive PHP environment information",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW],
      aggressivity: {
        minRequests: 1,
        maxRequests: PHPINFO_PATHS.length,
      },
    },

    initState: () => ({ phpinfoPaths: [], basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
