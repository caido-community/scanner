<script setup lang="ts">
import { computed } from "vue";

import { QueuePreview, QueueTable } from "@/components/queue";
import { useQueueService } from "@/services/queue";

const queueService = useQueueService();
const state = computed(() => queueService.getState());
const selectionState = computed(() => queueService.getSelectionState());
const selectedTask = computed(() => {
  if (state.value.type !== "Success" || selectionState.value.type === "None") {
    return undefined;
  }

  const taskId = selectionState.value.taskId;
  return state.value.tasks.find((task) => task.id === taskId);
});
</script>

<template>
  <div class="h-full flex flex-col gap-1 min-h-0">
    <QueueTable v-if="state.type === 'Success'" :state="state" />
    <QueuePreview
      v-if="selectedTask"
      :task="selectedTask"
      :selection-state="selectionState"
    />
  </div>
</template>
