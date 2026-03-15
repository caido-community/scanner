import type { CheckMetadata } from "engine";
import type { QueueTask } from "shared";

export const formatTaskId = (taskId: string): string => {
  return taskId.replace(/^pscan-/, "");
};

export const formatHost = (task: QueueTask): string => {
  if (task.request.port === 80 || task.request.port === 443) {
    return task.request.host;
  }

  return `${task.request.host}:${task.request.port}`;
};

export const formatPathWithQuery = (task: QueueTask): string => {
  if (task.request.query === "") {
    return task.request.path;
  }

  return `${task.request.path}?${task.request.query}`;
};

export const getCheckDisplayNames = ({
  checkIDs,
  checks,
}: {
  checkIDs: string[];
  checks: CheckMetadata[];
}): string[] => {
  const checksById = new Map(checks.map((check) => [check.id, check.name]));

  return checkIDs.map((checkID) => checksById.get(checkID) ?? checkID);
};
