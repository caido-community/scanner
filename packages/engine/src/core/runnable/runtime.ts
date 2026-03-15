import { type SDK } from "caido:plugin";
import {
  type Request,
  type RequestSpec,
  type RequestSpecRaw,
  type Response,
} from "caido:utils";

import { type CheckOutput } from "../../types/check";
import {
  type RuntimeContext,
  type ScanConfig,
  type ScanEvents,
  type ScanTarget,
} from "../../types/runner";
import { parseHtmlFromString } from "../../utils/html/parser";
import { type ParsedHtml } from "../../utils/html/types";
import { createPrefixedRandomId } from "../../utils/random";
import { ScanRunnableError, ScanRunnableErrorCode } from "../errors";

type RequestQueue = {
  enqueue: (
    request: RequestSpec | RequestSpecRaw,
    pendingRequestID: string,
    targetRequestID: string,
    checkID: string,
  ) => Promise<{ request: Request; response: Response }>;
};

/**
 * Creates the runtime helpers that `createRunnable()` uses while executing checks.
 *
 * It returns one helper for building the per-target runtime context seen by checks
 * and another for wrapping the SDK so outgoing requests flow through the scan queue
 * and emit scan events.
 */
export const createRuntimeAccessors = ({
  sdk,
  config,
  dependencies,
  htmlCache,
  requestQueue,
  emit,
}: {
  sdk: SDK;
  config: ScanConfig;
  dependencies: Map<string, CheckOutput>;
  htmlCache: Map<string, ParsedHtml>;
  requestQueue: RequestQueue;
  emit: <T extends keyof ScanEvents>(event: T, data: ScanEvents[T]) => void;
}) => {
  const createRuntimeContext = (
    target: ScanTarget,
    runtimeSdk: SDK,
  ): RuntimeContext => {
    return {
      target,
      config,
      sdk: runtimeSdk,
      runtime: {
        html: {
          parse: async (requestID: string) => {
            const cachedHtml = htmlCache.get(requestID);
            if (cachedHtml !== undefined) {
              return cachedHtml;
            }

            const request = await sdk.requests.get(requestID);
            if (request === undefined) {
              throw new ScanRunnableError(
                `Request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            if (request.response === undefined) {
              throw new ScanRunnableError(
                `Response for request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            const body = request.response.getBody();
            if (body === undefined) {
              throw new ScanRunnableError(
                `Body for request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            const parsedHtml = parseHtmlFromString(body.toText());
            htmlCache.set(requestID, parsedHtml);
            return parsedHtml;
          },
        },
        dependencies: {
          get: (key: string) => {
            return dependencies.get(key);
          },
        },
      },
    };
  };

  const createWrappedSdk = (checkID: string, targetRequestID: string): SDK => {
    return {
      ...sdk,
      requests: {
        inScope: (request: Request | RequestSpec) => {
          return sdk.requests.inScope(request);
        },
        query: () => {
          return sdk.requests.query();
        },
        matches: (filter: string, request: Request, response?: Response) => {
          return sdk.requests.matches(filter, request, response);
        },
        get: async (id: string) => {
          return sdk.requests.get(id);
        },
        send: async (request: RequestSpec | RequestSpecRaw) => {
          const pendingRequestID = createPrefixedRandomId("req-");

          emit("scan:request-pending", {
            pendingRequestID,
            targetRequestID,
            checkID,
          });

          return requestQueue.enqueue(
            request,
            pendingRequestID,
            targetRequestID,
            checkID,
          );
        },
      } as unknown as SDK["requests"],
    } as SDK;
  };

  return {
    createRuntimeContext,
    createWrappedSdk,
  };
};
