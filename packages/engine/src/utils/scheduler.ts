export type SchedulerSnapshot = {
  concurrency: number;
  pending: number;
  running: number;
};

export type SchedulerJobHandle<T> = {
  promise: Promise<T>;
  cancel: (reason: string) => boolean;
};

type SchedulerListener = (snapshot: SchedulerSnapshot) => void;

type PendingJob<T> = {
  run: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  state: "pending" | "running";
};

type Scheduler = {
  schedule: <T>(run: () => Promise<T>) => SchedulerJobHandle<T>;
  setConcurrency: (concurrency: number) => void;
  clearPending: (reason: string) => void;
  getSnapshot: () => SchedulerSnapshot;
  onSnapshot: (listener: SchedulerListener) => () => void;
  onIdle: () => Promise<void>;
};

export const createSchedulerSnapshot = ({
  concurrency,
  pending,
  running,
}: SchedulerSnapshot): SchedulerSnapshot => ({
  concurrency,
  pending,
  running,
});

const createCancellationError = (reason: string): Error => new Error(reason);

export const createScheduler = (initialConcurrency: number): Scheduler => {
  let concurrency = initialConcurrency;
  let running = 0;
  const queue: PendingJob<unknown>[] = [];
  const listeners = new Set<SchedulerListener>();
  const idleWaiters = new Set<() => void>();

  const getSnapshot = (): SchedulerSnapshot =>
    createSchedulerSnapshot({
      concurrency,
      pending: queue.length,
      running,
    });

  const notify = () => {
    const snapshot = getSnapshot();
    for (const listener of listeners) {
      listener(snapshot);
    }

    if (snapshot.pending === 0 && snapshot.running === 0) {
      for (const resolve of idleWaiters) {
        resolve();
      }
      idleWaiters.clear();
    }
  };

  const drain = () => {
    while (running < concurrency && queue.length > 0) {
      const next = queue.shift();
      if (next === undefined) {
        continue;
      }

      next.state = "running";
      running += 1;
      notify();

      next
        .run()
        .then((value) => {
          next.resolve(value);
        })
        .catch((error: unknown) => {
          if (error instanceof Error) {
            next.reject(error);
            return;
          }

          next.reject(new Error(String(error)));
        })
        .finally(() => {
          running -= 1;
          notify();
          drain();
        });
    }
  };

  const schedule = <T>(run: () => Promise<T>): SchedulerJobHandle<T> => {
    let job: PendingJob<T> | undefined;

    const promise = new Promise<T>((resolve, reject) => {
      job = {
        run,
        resolve,
        reject,
        state: "pending",
      };
      queue.push(job as PendingJob<unknown>);
      notify();
      drain();
    });

    return {
      promise,
      cancel: (reason: string) => {
        if (job === undefined || job.state !== "pending") {
          return false;
        }

        const index = queue.indexOf(job as PendingJob<unknown>);
        if (index === -1) {
          return false;
        }

        queue.splice(index, 1);
        job.reject(createCancellationError(reason));
        notify();
        return true;
      },
    };
  };

  return {
    schedule,
    setConcurrency: (nextConcurrency: number) => {
      concurrency = nextConcurrency;
      notify();
      drain();
    },
    clearPending: (reason: string) => {
      while (queue.length > 0) {
        const next = queue.shift();
        if (next === undefined) {
          continue;
        }

        next.reject(createCancellationError(reason));
      }
      notify();
    },
    getSnapshot,
    onSnapshot: (listener: SchedulerListener) => {
      listeners.add(listener);
      listener(getSnapshot());
      return () => {
        listeners.delete(listener);
      };
    },
    onIdle: () => {
      const snapshot = getSnapshot();
      if (snapshot.pending === 0 && snapshot.running === 0) {
        return Promise.resolve();
      }

      return new Promise<void>((resolve) => {
        idleWaiters.add(resolve);
      });
    },
  };
};
