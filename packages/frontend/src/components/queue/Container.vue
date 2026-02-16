<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import Column from "primevue/column";
import DataTable from "primevue/datatable";

import { useQueueService } from "@/services/queue";
import { type QueueState } from "@/types/queue";

const { state } = defineProps<{
  state: QueueState & { type: "Success" };
}>();

const queueService = useQueueService();

const clearQueue = () => {
  queueService.clearQueue();
};

const getStatusIcon = (status: string) => {
  return status === "running" ? "fas fa-spinner fa-spin" : "fas fa-clock";
};

const getStatusLabel = (status: string) => {
  return status === "running" ? "Running" : "Pending";
};
</script>

<template>
  <Card
    class="h-full"
    :pt="{
      body: { class: 'h-full p-0' },
      content: { class: 'h-full flex flex-col' },
    }"
  >
    <template #content>
      <div class="flex justify-between items-center p-4 gap-4">
        <div class="flex-1">
          <h3 class="text-lg font-semibold">Passive Scanning Queue</h3>
          <p class="text-sm text-surface-300 flex-1">
            Monitor passive vulnerability scanning tasks in progress.
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

      <DataTable
        :value="state.tasks"
        scrollable
        scroll-height="flex"
        striped-rows
        size="small"
        class="flex-1"
      >
        <template #empty>
          <div class="flex justify-center items-center">
            <span class="text-surface-400">No tasks in queue</span>
          </div>
        </template>

        <Column field="id" header="ID" class="min-w-48">
          <template #body="{ data }">
            <div class="font-mono text-sm">{{ data.id }}</div>
          </template>
        </Column>

        <Column field="requestID" header="Request ID" class="min-w-48">
          <template #body="{ data }">
            <div class="font-mono text-sm">{{ data.requestID }}</div>
          </template>
        </Column>

        <Column field="status" header="Status" class="w-32">
          <template #body="{ data }">
            <div class="flex items-center gap-2">
              <i :class="getStatusIcon(data.status)" class="text-sm"></i>
              <span class="capitalize text-sm">{{
                getStatusLabel(data.status)
              }}</span>
            </div>
          </template>
        </Column>
      </DataTable>
    </template>
  </Card>
</template>
