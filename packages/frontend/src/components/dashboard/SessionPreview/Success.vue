<script setup lang="ts">
import Card from "primevue/card";
import ProgressBar from "primevue/progressbar";
import { type Session } from "shared";

import { ChecksTable } from "./ChecksTable";
import Header from "./Header.vue";
import { useForm } from "./useForm";

const props = defineProps<{
  session: Session;
}>();

const {
  timeSinceCreated,
  progress,
  requestsSent,
  requestsPending,
  requestsFailed,
  severityOrder,
  checksCompleted,
  checksFailed,
  checksRunning,
  findingsBySeverity,
  getSeverityBadgeColor,
} = useForm(props);
</script>

<template>
  <Card
    class="h-full"
    :pt="{
      body: { class: 'h-full p-0 min-h-0' },
      content: { class: 'h-full flex flex-col' },
      header: { class: 'bg-surface-800' },
      root: { style: 'min-height: 0' },
    }"
  >
    <template #header>
      <Header :session="session" />
    </template>

    <template #content>
      <div class="flex flex-col h-full">
        <div class="flex flex-col gap-4 p-4">
          <div class="flex items-start justify-between gap-4">
            <div class="flex flex-col gap-2 flex-1">
              <span class="text-sm text-surface-300 font-medium">Created</span>
              <span class="text-sm text-surface-200 font-medium">
                {{ timeSinceCreated }}
              </span>
            </div>

            <div class="flex flex-col gap-2 flex-1">
              <span class="text-sm text-surface-300 font-medium">Findings</span>
              <div class="flex flex-wrap gap-2">
                <div
                  v-for="severity in severityOrder"
                  v-show="findingsBySeverity[severity] > 0"
                  :key="severity"
                  :class="[
                    'px-2 py-1 rounded-md border text-xs font-medium',
                    getSeverityBadgeColor(severity),
                  ]"
                >
                  {{
                    severity.charAt(0).toUpperCase() +
                    severity.slice(1).toLowerCase()
                  }}: {{ findingsBySeverity[severity] }}
                </div>
                <div
                  v-if="
                    Object.values(findingsBySeverity).every(
                      (count) => count === 0,
                    )
                  "
                  class="py-1 rounded-md text-xs text-surface-500 italic h-[23px] flex items-center"
                >
                  No findings found
                </div>
              </div>
            </div>
          </div>

          <div
            v-if="session.kind === 'Running' || session.kind === 'Done'"
            class="flex flex-col gap-3 w-full"
          >
            <div class="flex items-center justify-between">
              <span class="text-sm text-surface-300 font-medium"
                >Scan Progress</span
              >
              <span class="text-sm text-surface-200 font-mono font-semibold">
                {{ progress }}%
              </span>
            </div>

            <ProgressBar
              :value="progress"
              class="w-full h-2"
              :show-value="false"
              :pt="{
                root: { class: 'bg-surface-700 rounded-full overflow-hidden' },
                value: {
                  class:
                    session.kind === 'Done'
                      ? 'h-full transition-all duration-300 ease-out bg-success-500'
                      : 'h-full transition-all duration-300 ease-out bg-secondary-400',
                },
              }"
            />
          </div>

          <div
            v-if="session.kind !== 'Error'"
            class="flex items-center justify-between text-xs"
          >
            <div class="flex items-center gap-4">
              <div class="flex items-center gap-2">
                <span class="text-surface-400">Requests sent:</span>
                <span class="text-surface-200 font-mono font-medium">{{
                  requestsSent
                }}</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-surface-400">Requests pending:</span>
                <span class="text-surface-200 font-mono font-medium">{{
                  requestsPending
                }}</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-surface-400">Requests failed:</span>
                <span class="text-surface-200 font-mono font-medium">{{
                  requestsFailed
                }}</span>
              </div>
              <div
                v-if="session.kind === 'Running'"
                class="flex items-center gap-2"
              >
                <span class="text-surface-400">Checks running:</span>
                <span class="text-surface-200 font-mono font-medium">{{
                  checksRunning.length
                }}</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-surface-400">Checks completed:</span>
                <span class="text-surface-200 font-mono font-medium">{{
                  checksCompleted
                }}</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-surface-400">Checks failed:</span>
                <span class="text-surface-200 font-mono font-medium">{{
                  checksFailed
                }}</span>
              </div>
            </div>
          </div>

          <div v-if="session.kind === 'Error'" class="flex flex-col gap-2">
            <div class="flex items-center justify-between">
              <span class="text-sm text-surface-300 font-medium">Error</span>
            </div>
            <div class="bg-surface-900 border border-surface-600 rounded p-3">
              <code
                class="text-sm text-red-400 font-mono whitespace-pre-wrap"
                >{{ session.error }}</code
              >
            </div>
          </div>
        </div>
        <ChecksTable :session="session" />
      </div>
    </template>
  </Card>
</template>
