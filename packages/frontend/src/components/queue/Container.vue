<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import { RecycleScroller } from "vue-virtual-scroller";

import { formatHost, formatPathWithQuery, formatTaskId } from "./utils";

import { useQueueService } from "@/services/queue";
import { type QueueState } from "@/types/queue";

const { state } = defineProps<{
  state: QueueState & { type: "Success" };
}>();

const queueService = useQueueService();
const rowHeight = 38;
const columnWidths = {
  task: "7%",
  host: "14%",
  method: "8%",
  path: "39%",
  status: "10%",
  created: "11%",
  finished: "11%",
} as const;

const clearQueue = () => {
  queueService.clearQueue();
};

const selectTask = (taskId: string) => {
  const task = state.tasks.find((currentTask) => currentTask.id === taskId);
  if (task === undefined) {
    return;
  }

  void queueService.selectTask(task);
};

const getStatusLabel = (status: string) => {
  switch (status) {
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "cancelled":
      return "Cancelled";
    default:
      return "Pending";
  }
};

const selectionState = () => queueService.getSelectionState();

const formatTimestamp = (timestamp?: number) => {
  if (timestamp === undefined) {
    return "—";
  }

  return new Date(timestamp).toLocaleTimeString();
};

const isSelectedTask = (taskId: string) => {
  const selection = selectionState();
  return selection.type !== "None" && selection.taskId === taskId;
};

const onTaskKeydown = (taskId: string) => {
  selectTask(taskId);
};
</script>

<template>
  <Card
    class="flex-1 min-h-0"
    :pt="{
      body: { class: 'h-full p-0 min-h-0' },
      content: { class: 'h-full flex flex-col min-h-0' },
      root: { style: 'min-height: 0' },
    }"
  >
    <template #content>
      <div class="flex justify-between items-center p-4 gap-4">
        <div class="flex-1">
          <h3 class="text-lg font-semibold">Passive Scanning Queue</h3>
          <p class="text-sm text-surface-300 flex-1">
            Monitor live and recent passive scanning tasks.
          </p>
        </div>

        <div class="flex gap-2 items-center">
          <Button
            label="Clear Queue"
            severity="secondary"
            size="small"
            icon="fas fa-trash"
            outlined
            @click="clearQueue"
          />
        </div>
      </div>

      <div
        v-if="state.tasks.length === 0"
        class="flex-1 min-h-0 flex items-center justify-center text-surface-400"
      >
        No tasks in queue
      </div>

      <div v-else class="flex-1 min-h-0 flex flex-col">
        <div class="overflow-y-scroll" style="scrollbar-gutter: stable">
          <table class="w-full border-spacing-0 border-separate table-fixed">
            <thead class="bg-surface-900">
              <tr class="text-surface-0/70">
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.task }"
                >
                  Task
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.host }"
                >
                  Host
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.method }"
                >
                  Method
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.path }"
                >
                  Path + Query
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.status }"
                >
                  Status
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.created }"
                >
                  Created
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.finished }"
                >
                  Finished
                </th>
              </tr>
            </thead>
          </table>
        </div>

        <RecycleScroller
          class="flex-1 overflow-auto"
          style="scrollbar-gutter: stable"
          :items="state.tasks"
          :item-size="rowHeight"
          key-field="id"
        >
          <template #default="{ item, index }">
            <table
              class="w-full h-[38px] border-spacing-0 border-separate table-fixed"
            >
              <tbody>
                <tr
                  class="h-[38px] cursor-pointer select-none outline-none transition-colors"
                  :class="
                    isSelectedTask(item.id)
                      ? 'bg-surface-700 text-surface-0'
                      : index % 2 === 0
                        ? 'bg-surface-800 hover:bg-surface-700/70'
                        : 'bg-surface-900 hover:bg-surface-700/70'
                  "
                  role="button"
                  tabindex="0"
                  @click="selectTask(item.id)"
                  @keydown.enter.prevent="onTaskKeydown(item.id)"
                  @keydown.space.prevent="onTaskKeydown(item.id)"
                >
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.task }"
                  >
                    <div class="text-sm font-mono truncate" :title="item.id">
                      {{ formatTaskId(item.id) }}
                    </div>
                  </td>
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.host }"
                  >
                    <div class="text-sm truncate" :title="formatHost(item)">
                      {{ formatHost(item) }}
                    </div>
                  </td>
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.method }"
                  >
                    <div class="text-sm truncate">
                      {{ item.request.method }}
                    </div>
                  </td>
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.path }"
                  >
                    <div
                      class="text-sm truncate"
                      :title="formatPathWithQuery(item)"
                    >
                      {{ formatPathWithQuery(item) }}
                    </div>
                  </td>
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.status }"
                  >
                    <div class="text-sm truncate">
                      {{ getStatusLabel(item.status) }}
                    </div>
                  </td>
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.created }"
                  >
                    <div class="text-sm text-surface-300">
                      {{ formatTimestamp(item.createdAt) }}
                    </div>
                  </td>
                  <td
                    class="h-[38px] leading-[normal] text-left border-0 py-0 px-2 align-middle"
                    :style="{ width: columnWidths.finished }"
                  >
                    <div class="text-sm text-surface-300">
                      {{
                        formatTimestamp(
                          item.status === "completed" ||
                            item.status === "failed" ||
                            item.status === "cancelled"
                            ? item.finishedAt
                            : undefined,
                        )
                      }}
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </template>
        </RecycleScroller>
      </div>
    </template>
  </Card>
</template>
