import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

type State = {
  candidates: string[];
};

const IIS_PATTERN = /Parent Directory/i;
const APACHE_TOMCAT_PATTERN = /\bDirectory Listing\b.*(Tomcat|Apache)/i;
const GENERAL_PARENT_PATTERN = /Parent directory/i;
const GENERAL_DIR_PATTERN = /\bDirectory\b/i;
const GENERAL_IMG_PATTERN = /[\s<]+IMG\s*=/i;

const toDirectory = (originalPath: string): string => {
  if (originalPath.endsWith("/")) {
    return originalPath;
  }

  const segments = originalPath.split("/");
  const last = segments[segments.length - 1];
  if (last !== undefined && last.includes(".")) {
    const parent = segments.slice(0, -1).join("/");
    return parent ? parent + "/" : "/";
  }
  return originalPath + "/";
};

const parentDirectory = (dirPath: string): string => {
  const withoutTrailing = dirPath.endsWith("/")
    ? dirPath.slice(0, -1)
    : dirPath;
  const parent = withoutTrailing.split("/").slice(0, -1).join("/");
  return parent ? parent + "/" : "/";
};

const checkDirectoryListing = (
  bodyText: string,
): {
  isListing: boolean;
  evidence?: string;
  confidence: "high" | "medium" | "low";
} => {
  let match = bodyText.match(IIS_PATTERN);
  if (match) {
    return { isListing: true, evidence: match[0], confidence: "medium" };
  }

  match = bodyText.match(APACHE_TOMCAT_PATTERN);
  if (match) {
    return { isListing: true, evidence: match[0], confidence: "high" };
  }

  match = bodyText.match(GENERAL_PARENT_PATTERN);
  if (match) {
    return { isListing: true, evidence: match[0], confidence: "low" };
  }

  const dirMatch = bodyText.match(GENERAL_DIR_PATTERN);
  const imgMatch = bodyText.match(GENERAL_IMG_PATTERN);
  if (dirMatch && imgMatch) {
    return { isListing: true, evidence: dirMatch[0], confidence: "low" };
  }

  return { isListing: false, confidence: "high" };
};

export default defineCheck<State>(({ step }) => {
  step("setupScan", (_, context) => {
    const initial = toDirectory(context.target.request.getPath());

    let candidates: string[] = [initial];
    if (context.config.aggressivity === ScanAggressivity.MEDIUM) {
      const parent1 = parentDirectory(initial);
      candidates = Array.from(new Set([initial, parent1]));
    } else if (context.config.aggressivity === ScanAggressivity.HIGH) {
      const parent1 = parentDirectory(initial);
      const parent2 = parentDirectory(parent1);
      candidates = Array.from(new Set([initial, parent1, parent2]));
    }

    return continueWith({
      nextStep: "testCandidate",
      state: { candidates },
    });
  });

  step("testCandidate", async (state, context) => {
    if (state.candidates.length === 0) {
      return done({ state });
    }

    const [current, ...remaining] = state.candidates;
    if (current === undefined) {
      return done({ state });
    }

    const spec = context.target.request.toSpec();
    spec.setMethod("GET");
    spec.setPath(current);
    spec.setQuery("");

    const result = await context.sdk.requests.send(spec);
    const response = result.response;

    if (response !== undefined && response.getCode() === 200) {
      const body = response.getBody();
      const bodyText = body?.toText() ?? "";

      const listingResult = checkDirectoryListing(bodyText);

      if (listingResult.isListing) {
        const severity =
          listingResult.confidence === "low" ? Severity.LOW : Severity.MEDIUM;

        return done({
          state,
          findings: [
            {
              name: "Directory Listing Enabled",
              description:
                "Directory listing appears enabled at `" +
                current +
                "`. This can expose sensitive files and internal structure." +
                (listingResult.evidence !== undefined
                  ? " Evidence: `" + listingResult.evidence + "`."
                  : ""),
              severity,
              correlation: {
                requestID: result.request.getId(),
                locations: [],
              },
            },
          ],
        });
      }
    }

    return continueWith({
      nextStep: "testCandidate",
      state: { candidates: remaining },
    });
  });

  return {
    metadata: {
      id: "directory-listing",
      name: "Directory Listing",
      description:
        "Detects web server directory listing exposure by probing directory paths and analyzing responses for listing markers.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW, Severity.MEDIUM],
      aggressivity: {
        minRequests: 1,
        maxRequests: 3,
      },
    },
    initState: (): State => ({ candidates: [] }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
