<script setup lang="ts">
import Card from "primevue/card";
import ProgressBar from "primevue/progressbar";
import { type Session } from "shared";
import { toRef } from "vue";

import { ChecksTable } from "./ChecksTable";
import FindingsView from "./FindingsView.vue";
import Header from "./Header.vue";
import { useForm } from "./useForm";

import FindingsBySeverity from "@/components/common/FindingsBySeverity.vue";

const { session } = defineProps<{
  session: Session;
}>();

const {
  timeSinceCreated,
  progress,
  requestsSent,
  requestsPending,
  requestsFailed,
  checksCompleted,
  checksFailed,
  checksRunning,
  findings,
  activeView,
  openFindings,
  backToSummary,
  sessionFindings,
  selectedFinding,
  selectedFindingId,
  selectFinding,
  selectedFindingRequestState,
  retryRequest,
  getStatusColor,
  onCancel,
  onDelete,
  onRerun,
  onConfirmDelete,
  onCancelDelete,
  onConfirmRerun,
  onCancelRerun,
  isCancelling,
  isDeleting,
  isRerunning,
  showDeleteDialog,
  showRerunDialog,
} = useForm(toRef(() => session));
</script>

<template>
  <div class="h-full min-h-0 flex flex-col gap-1">
    <Card
      class="h-fit"
      :pt="{
        body: { class: 'h-fit p-0' },
        content: { class: 'h-fit flex flex-col' },
      }"
    >
      <template #content>
        <Header
          :session="session"
          :active-view="activeView"
          :can-show-findings="session.kind !== 'Error'"
          :on-open-findings="openFindings"
          :on-back="backToSummary"
          :on-cancel="onCancel"
          :on-delete="onDelete"
          :on-rerun="onRerun"
          :on-confirm-delete="onConfirmDelete"
          :on-cancel-delete="onCancelDelete"
          :on-confirm-rerun="onConfirmRerun"
          :on-cancel-rerun="onCancelRerun"
          :is-cancelling="isCancelling"
          :is-deleting="isDeleting"
          :is-rerunning="isRerunning"
          :show-delete-dialog="showDeleteDialog"
          :show-rerun-dialog="showRerunDialog"
          :get-status-color="getStatusColor"
        />
      </template>
    </Card>

    <FindingsView
      v-if="activeView === 'findings'"
      :findings="sessionFindings"
      :selected-finding="selectedFinding"
      :selected-finding-id="selectedFindingId"
      :selected-finding-request-state="selectedFindingRequestState"
      :retry-request="retryRequest"
      @select-finding="selectFinding"
    />

    <Card
      v-else
      class="flex-1 min-h-0"
      :pt="{
        body: { class: 'h-full p-0 min-h-0' },
        content: { class: 'h-full flex flex-col min-h-0' },
        root: { style: 'min-height: 0' },
      }"
    >
      <template #content>
        <div class="flex flex-col h-full min-h-0">
          <div class="flex flex-col gap-4 p-4">
            <div class="flex items-start justify-between gap-4">
              <div class="flex flex-col gap-2 flex-1">
                <span class="text-sm text-surface-300 font-medium"
                  >Created</span
                >
                <span class="text-sm text-surface-200 font-medium">
                  {{ timeSinceCreated }}
                </span>
              </div>

              <div class="flex flex-col gap-2 flex-1">
                <span class="text-sm text-surface-300 font-medium"
                  >Findings</span
                >
                <FindingsBySeverity :findings="findings" />
              </div>
            </div>

            <div
              v-if="
                session.kind === 'Running' ||
                session.kind === 'Done' ||
                session.kind === 'Interrupted'
              "
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
                  root: {
                    class: 'bg-surface-700 rounded-full overflow-hidden',
                  },
                  value: {
                    class:
                      session.kind === 'Done'
                        ? 'h-full transition-all duration-300 ease-out bg-success-500'
                        : session.kind === 'Interrupted'
                          ? 'h-full transition-all duration-300 ease-out bg-orange-500'
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
  </div>
</template>
