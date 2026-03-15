import { describe, expect, it } from "vitest";

import { createScheduler } from "./scheduler";

describe("createScheduler", () => {
  it("runs jobs in FIFO order with bounded concurrency", async () => {
    const scheduler = createScheduler(2);
    const events: string[] = [];

    const first = scheduler.schedule(async () => {
      events.push("start-1");
      await new Promise((resolve) => setTimeout(resolve, 20));
      events.push("finish-1");
      return "first";
    });

    const second = scheduler.schedule(async () => {
      events.push("start-2");
      await new Promise((resolve) => setTimeout(resolve, 5));
      events.push("finish-2");
      return "second";
    });

    const third = scheduler.schedule(async () => {
      events.push("start-3");
      return await Promise.resolve("third");
    });

    await expect(first.promise).resolves.toBe("first");
    await expect(second.promise).resolves.toBe("second");
    await expect(third.promise).resolves.toBe("third");

    expect(events.indexOf("start-1")).toBeLessThan(events.indexOf("start-3"));
    expect(events.indexOf("start-2")).toBeLessThan(events.indexOf("start-3"));
  });

  it("cancels pending work", async () => {
    const scheduler = createScheduler(1);

    const first = scheduler.schedule(
      async () =>
        await new Promise<string>((resolve) => {
          setTimeout(() => resolve("first"), 20);
        }),
    );
    const second = scheduler.schedule(
      async () => await Promise.resolve("second"),
    );

    expect(second.cancel("cancelled")).toBe(true);
    await expect(second.promise).rejects.toThrow("cancelled");
    await expect(first.promise).resolves.toBe("first");
  });

  it("resolves onIdle after queued and running work completes", async () => {
    const scheduler = createScheduler(1);

    scheduler.schedule(
      async () =>
        await new Promise<string>((resolve) => {
          setTimeout(() => resolve("done"), 10);
        }),
    );

    await expect(scheduler.onIdle()).resolves.toBeUndefined();
    expect(scheduler.getSnapshot()).toEqual({
      concurrency: 1,
      pending: 0,
      running: 0,
    });
  });

  it("notifies snapshots when work changes", async () => {
    const scheduler = createScheduler(1);
    const snapshots: Array<{ pending: number; running: number }> = [];

    const unsubscribe = scheduler.onSnapshot((snapshot) => {
      snapshots.push({
        pending: snapshot.pending,
        running: snapshot.running,
      });
    });

    const job = scheduler.schedule(async () => await Promise.resolve("done"));
    await job.promise;
    unsubscribe();

    expect(snapshots).toContainEqual({ pending: 0, running: 0 });
    expect(snapshots).toContainEqual({ pending: 1, running: 0 });
    expect(snapshots).toContainEqual({ pending: 0, running: 1 });
  });
});
