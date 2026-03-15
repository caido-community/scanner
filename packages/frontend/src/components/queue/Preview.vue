<script setup lang="ts">
import Card from "primevue/card";
import Splitter from "primevue/splitter";
import SplitterPanel from "primevue/splitterpanel";
import { type QueueTask } from "shared";
import { computed } from "vue";

import RequestEditor from "./RequestEditor.vue";
import { formatHost, formatPathWithQuery, formatTaskId } from "./utils";

import { type QueueSelectionState } from "@/types/queue";

const { task, selectionState } = defineProps<{
  task: QueueTask;
  selectionState: QueueSelectionState;
}>();

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

const formatTimestamp = (timestamp?: number) => {
  if (timestamp === undefined) {
    return "—";
  }

  return new Date(timestamp).toLocaleTimeString();
};

const finishedAt = computed(() => {
  switch (task.status) {
    case "completed":
    case "failed":
    case "cancelled":
      return task.finishedAt;
    default:
      return undefined;
  }
});
</script>

<template>
  <Card
    class="h-[52rem] flex-shrink-0"
    :pt="{
      body: { class: 'h-full p-0 min-h-0' },
      content: { class: 'h-full flex flex-col min-h-0' },
      root: { style: 'min-height: 0' },
    }"
  >
    <template #content>
      <div class="h-full flex flex-col min-h-0 p-4 gap-4">
        <div class="flex items-center justify-between gap-4">
          <div>
            <h3 class="text-lg font-semibold">Preview</h3>
            <p class="text-sm text-surface-300">
              Request details for the selected passive scan task.
            </p>
          </div>
        </div>

        <div class="grid grid-cols-2 xl:grid-cols-4 gap-4 text-sm">
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Host</span>
            <span class="font-medium truncate" :title="formatHost(task)">
              {{ formatHost(task) }}
            </span>
          </div>
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Method</span>
            <span class="font-medium">{{ task.request.method }}</span>
          </div>
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Path + Query</span>
            <span
              class="font-medium truncate"
              :title="formatPathWithQuery(task)"
            >
              {{ formatPathWithQuery(task) }}
            </span>
          </div>
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Status</span>
            <span class="font-medium">
              {{ getStatusLabel(task.status) }}
            </span>
          </div>
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Created</span>
            <span class="font-medium">
              {{ formatTimestamp(task.createdAt) }}
            </span>
          </div>
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Finished</span>
            <span class="font-medium">
              {{ formatTimestamp(finishedAt) }}
            </span>
          </div>
          <div class="flex flex-col gap-1 min-w-0">
            <span class="text-surface-400">Task</span>
            <span class="font-mono font-medium">
              {{ formatTaskId(task.id) }}
            </span>
          </div>
        </div>

        <Splitter layout="vertical" class="flex-1 min-h-0">
          <SplitterPanel :size="100" :min-size="25" class="h-full min-h-0">
            <div class="h-full min-h-0 border border-surface-700 rounded">
              <div
                v-if="selectionState.type === 'Loading'"
                class="h-full min-h-0 p-3 text-sm text-surface-400"
              >
                Loading request...
              </div>
              <div
                v-else-if="selectionState.type === 'Error'"
                class="h-full min-h-0 p-3 text-sm text-red-300"
              >
                {{ selectionState.error }}
              </div>
              <RequestEditor
                v-else-if="selectionState.type === 'Success'"
                :raw="selectionState.request.raw"
              />
            </div>
          </SplitterPanel>
        </Splitter>
      </div>
    </template>
  </Card>
</template>
