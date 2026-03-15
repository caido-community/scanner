import { type SDK } from "caido:plugin";
import {
  type RequestResponse,
  type RequestSpec,
  type RequestSpecRaw,
} from "caido:utils";

import {
  type InterruptReason,
  type ScanConfig,
  type ScanEvents,
} from "../types/runner";
import { createScheduler } from "../utils/scheduler";

import {
  ScanRunnableError,
  ScanRunnableErrorCode,
  ScanRunnableInterruptedError,
} from "./errors";

type QueuedRequest = {
  request: RequestSpec | RequestSpecRaw;
  resolve: (value: RequestResponse) => void;
  reject: (error: Error) => void;
  pendingRequestID: string;
  targetRequestID: string;
  checkID: string;
};

type RequestQueue = {
  enqueue: (
    request: RequestSpec | RequestSpecRaw,
    pendingRequestID: string,
    targetRequestID: string,
    checkID: string,
  ) => Promise<RequestResponse>;
  clearPending: (reason: string) => void;
  onIdle: () => Promise<void>;
};

export const computeDelayNeeded = ({
  now,
  lastRequestTime,
  requestsDelayMs,
}: {
  now: number;
  lastRequestTime: number;
  requestsDelayMs: number;
}): number => {
  return Math.max(0, requestsDelayMs - (now - lastRequestTime));
};

export const canStartQueuedRequest = ({
  queueLength,
  activeRequests,
  concurrentRequests,
}: {
  queueLength: number;
  activeRequests: number;
  concurrentRequests: number;
}): boolean => {
  return queueLength > 0 && activeRequests < concurrentRequests;
};

export const createRequestQueue = ({
  sdk,
  config,
  emit,
  getInterruptReason,
}: {
  sdk: SDK;
  config: ScanConfig;
  emit: (event: keyof ScanEvents, data: ScanEvents[keyof ScanEvents]) => void;
  getInterruptReason: () => InterruptReason | undefined;
}): RequestQueue => {
  let lastRequestTime = 0;
  let requestLock = Promise.resolve();
  const scheduler = createScheduler(config.concurrentRequests);

  const processRequest = async (item: QueuedRequest): Promise<void> => {
    try {
      if (getInterruptReason()) {
        throw new ScanRunnableInterruptedError(getInterruptReason()!);
      }

      if (config.requestsDelayMs > 0) {
        requestLock = requestLock.then(async () => {
          const delayNeeded = computeDelayNeeded({
            now: Date.now(),
            lastRequestTime,
            requestsDelayMs: config.requestsDelayMs,
          });

          if (delayNeeded > 0) {
            await new Promise((resolve) => setTimeout(resolve, delayNeeded));
          }

          lastRequestTime = Date.now();
        });

        await requestLock;
      }

      const requestTimeoutSeconds =
        config.requestTimeout ?? config.checkTimeout;
      const requestTimeoutMs = requestTimeoutSeconds * 1000;
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          reject(
            new Error(`Request timeout after ${requestTimeoutSeconds} seconds`),
          );
        }, requestTimeoutMs);
      });

      const result = await Promise.race([
        sdk.requests.send(item.request),
        timeoutPromise,
      ]).finally(() => {
        if (timeoutId !== undefined) {
          clearTimeout(timeoutId);
        }
      });

      emit("scan:request-completed", {
        pendingRequestID: item.pendingRequestID,
        requestID: result.request.getId(),
        responseID: result.response.getId(),
        checkID: item.checkID,
        targetRequestID: item.targetRequestID,
      });

      item.resolve(result);
    } catch (error) {
      if (error instanceof ScanRunnableInterruptedError) {
        emit("scan:request-failed", {
          pendingRequestID: item.pendingRequestID,
          error: error.message,
          targetRequestID: item.targetRequestID,
          checkID: item.checkID,
        });
        item.reject(error);
        return;
      }
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      emit("scan:request-failed", {
        pendingRequestID: item.pendingRequestID,
        error: errorMessage,
        targetRequestID: item.targetRequestID,
        checkID: item.checkID,
      });

      item.reject(
        new ScanRunnableError(
          `Request ID: ${item.targetRequestID} failed: ${errorMessage}`,
          ScanRunnableErrorCode.REQUEST_FAILED,
        ),
      );
    }
  };

  const enqueue = async (
    request: RequestSpec | RequestSpecRaw,
    pendingRequestID: string,
    targetRequestID: string,
    checkID: string,
  ): Promise<RequestResponse> => {
    if (getInterruptReason()) {
      throw new ScanRunnableInterruptedError(getInterruptReason()!);
    }

    const item: QueuedRequest = {
      request,
      pendingRequestID,
      targetRequestID,
      checkID,
      resolve: () => undefined,
      reject: () => undefined,
    };

    return scheduler
      .schedule(async () => {
        return await new Promise<RequestResponse>((resolve, reject) => {
          item.resolve = resolve;
          item.reject = reject;
          void processRequest(item);
        });
      })
      .promise.catch((error: unknown) => {
        const interruptReason = getInterruptReason();
        if (
          interruptReason !== undefined &&
          error instanceof Error &&
          error.message === interruptReason
        ) {
          throw new ScanRunnableInterruptedError(interruptReason);
        }

        throw error;
      });
  };

  return {
    enqueue,
    clearPending: (reason: string) => {
      scheduler.clearPending(reason);
    },
    onIdle: async () => {
      await scheduler.onIdle();
    },
  };
};
