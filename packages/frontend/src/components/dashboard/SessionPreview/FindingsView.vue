<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import Splitter from "primevue/splitter";
import SplitterPanel from "primevue/splitterpanel";

import { type RequestPreviewState, type SessionFinding } from "./utils";

import RequestEditor from "@/components/queue/RequestEditor.vue";
import ResponseEditor from "@/components/queue/ResponseEditor.vue";

const {
  findings,
  selectedFinding,
  selectedFindingId,
  selectedFindingRequestState,
  retryRequest,
} = defineProps<{
  findings: SessionFinding[];
  selectedFinding: SessionFinding | undefined;
  selectedFindingId: string | undefined;
  selectedFindingRequestState: RequestPreviewState;
  retryRequest: (requestId: string) => void;
}>();

const emit = defineEmits<{
  (e: "selectFinding", findingId: string): void;
}>();

const getSeverityClasses = (severity: string) => {
  switch (severity) {
    case "critical":
      return "bg-red-500/20 text-red-300 border-red-500/30";
    case "high":
      return "bg-orange-500/20 text-orange-300 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/20 text-yellow-300 border-yellow-500/30";
    case "low":
      return "bg-blue-500/20 text-blue-300 border-blue-500/30";
    default:
      return "bg-surface-700 text-surface-200 border-surface-600";
  }
};
</script>

<template>
  <div class="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden">
    <div
      v-if="findings.length === 0"
      class="flex-1 min-h-0 flex items-center justify-center text-surface-400"
    >
      No findings created for this session yet.
    </div>

    <div
      v-else
      class="flex-1 min-h-0 min-w-0 grid grid-cols-1 lg:grid-cols-[minmax(20rem,0.9fr)_minmax(0,1.35fr)] gap-1"
    >
      <Card
        class="h-80 min-h-80 overflow-hidden lg:h-full lg:min-h-0"
        :pt="{
          body: { class: 'h-full p-0 min-h-0' },
          content: { class: 'h-full min-h-0 flex flex-col' },
        }"
      >
        <template #content>
          <div class="h-full min-h-0 overflow-auto p-2 flex flex-col gap-2">
            <button
              v-for="finding in findings"
              :key="finding.id"
              type="button"
              :class="[
                'w-full min-w-0 text-left rounded border px-4 py-3 transition-colors',
                selectedFindingId === finding.id
                  ? 'border-secondary-400 bg-surface-700'
                  : 'border-surface-700 bg-surface-800 hover:bg-surface-700/80',
              ]"
              @click="emit('selectFinding', finding.id)"
            >
              <div class="flex items-start justify-between gap-3">
                <div class="min-w-0 flex-1">
                  <div class="font-medium text-surface-50 truncate">
                    {{ finding.name }}
                  </div>
                  <div class="text-sm text-surface-300 mt-1 line-clamp-2">
                    {{ finding.description }}
                  </div>
                </div>

                <span
                  :class="[
                    'shrink-0 rounded border px-2 py-1 text-xs font-medium uppercase tracking-wide',
                    getSeverityClasses(finding.severity),
                  ]"
                >
                  {{ finding.severity }}
                </span>
              </div>

              <div class="mt-3 truncate text-xs text-surface-300">
                <span class="text-surface-400">Check:</span>
                {{ finding.checkID }}
              </div>
            </button>
          </div>
        </template>
      </Card>

      <div
        v-if="selectedFinding !== undefined"
        class="h-full min-h-0 flex flex-col gap-1"
      >
        <Card
          class="h-64 min-h-64"
          :pt="{
            body: { class: 'h-full p-0 min-h-0' },
            content: { class: 'h-full min-h-0 flex flex-col' },
          }"
        >
          <template #content>
            <div class="h-full min-h-0 overflow-auto p-4">
              <div class="min-w-0">
                <h4 class="text-base font-semibold truncate">
                  {{ selectedFinding.name }}
                </h4>
                <p
                  class="mt-2 select-text text-sm text-surface-300 whitespace-pre-wrap break-words"
                >
                  {{ selectedFinding.description }}
                </p>
              </div>
            </div>
          </template>
        </Card>

        <Card
          class="flex-1 min-h-0"
          :pt="{
            body: { class: 'h-full p-0 min-h-0' },
            content: { class: 'h-full min-h-0 flex flex-col' },
            root: { style: 'min-height: 0' },
          }"
        >
          <template #content>
            <div class="h-full min-h-0 flex flex-col">
              <div
                class="min-h-0 min-w-0 flex-1 rounded bg-surface-900 overflow-hidden"
              >
                <div
                  v-if="selectedFindingRequestState.type === 'Loading'"
                  class="h-full min-h-0 p-3 text-sm text-surface-400"
                >
                  Loading request...
                </div>
                <div
                  v-else-if="selectedFindingRequestState.type === 'Error'"
                  class="h-full min-h-0 p-3 flex flex-col gap-3 text-sm text-red-300"
                >
                  <span>{{ selectedFindingRequestState.error }}</span>
                  <div>
                    <Button
                      label="Retry"
                      size="small"
                      outlined
                      severity="secondary"
                      @click="retryRequest(selectedFinding.findingRequestID)"
                    />
                  </div>
                </div>
                <Splitter
                  v-else-if="selectedFindingRequestState.type === 'Success'"
                  class="h-full min-h-0"
                >
                  <SplitterPanel
                    :size="50"
                    :min-size="20"
                    class="min-h-0 overflow-hidden"
                  >
                    <RequestEditor
                      :raw="selectedFindingRequestState.request.raw"
                    />
                  </SplitterPanel>
                  <SplitterPanel
                    :size="50"
                    :min-size="20"
                    class="min-h-0 overflow-hidden"
                  >
                    <ResponseEditor
                      :raw="selectedFindingRequestState.response.raw"
                    />
                  </SplitterPanel>
                </Splitter>
                <div v-else class="h-full min-h-0 p-3 text-sm text-surface-400">
                  Select a finding to preview its request.
                </div>
              </div>
            </div>
          </template>
        </Card>
      </div>

      <Card
        v-else
        class="h-full min-h-0"
        :pt="{
          body: { class: 'h-full p-0 min-h-0' },
          content: {
            class: 'h-full min-h-0 flex items-center justify-center',
          },
        }"
      >
        <template #content>
          <div class="text-surface-400">Select a finding to preview it.</div>
        </template>
      </Card>
    </div>
  </div>
</template>
