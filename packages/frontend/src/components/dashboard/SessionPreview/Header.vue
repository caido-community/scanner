<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import { type Session } from "shared";
import { computed, toRef } from "vue";

import { useForm } from "./useForm";

import { useScannerService } from "@/services/scanner";

const { session } = defineProps<{
  session: Session;
}>();

const {
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

const scannerService = useScannerService();

const hasExecutionTrace = computed(() => {
  if (session.kind === "Done" || session.kind === "Interrupted") {
    return session.hasExecutionTrace;
  }

  return false;
});

const onDownloadTrace = () => {
  scannerService.downloadExecutionTrace(session.id);
};
</script>

<template>
  <div class="flex items-center justify-between gap-4 px-4 pt-4">
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2">
        <span class="text-base font-medium">{{ session.title }}</span>
        <span class="text-xs text-surface-400 font-mono">{{ session.id }}</span>
      </div>
      <div class="flex items-center gap-2">
        <div
          :class="['w-2 h-2 rounded-full', getStatusColor(session.kind)]"
        ></div>
        <span
          :class="['text-xs rounded text-surface-100 uppercase tracking-wide']"
        >
          <span :class="{ shimmer: session.kind === 'Running' }">{{
            session.kind
          }}</span>
          <span
            v-if="session.kind === 'Interrupted' && session.reason"
            class="text-xs text-surface-400 normal-case ml-1"
          >
            ({{ session.reason }})
          </span>
        </span>
      </div>
    </div>

    <div class="flex items-center gap-2">
      <Button
        v-if="session.kind === 'Running'"
        label="Cancel"
        severity="danger"
        :loading="isCancelling"
        outlined
        size="small"
        @click="onCancel"
      />

      <Button
        v-if="hasExecutionTrace"
        label="Download Trace"
        severity="contrast"
        outlined
        size="small"
        icon="fas fa-download"
        @click="onDownloadTrace"
      />

      <Button
        v-if="
          session.kind === 'Done' ||
          session.kind === 'Interrupted' ||
          session.kind === 'Error'
        "
        label="Rerun"
        :loading="isRerunning"
        outlined
        size="small"
        severity="info"
        @click="onRerun"
      />

      <Button
        label="Delete"
        severity="danger"
        :loading="isDeleting"
        outlined
        size="small"
        @click="onDelete"
      />
    </div>
  </div>

  <Dialog
    v-model:visible="showDeleteDialog"
    modal
    header="Delete Session"
    :style="{ width: '25rem' }"
  >
    <div class="flex flex-col gap-4">
      <p class="text-surface-300">Do you want to delete this session?</p>
    </div>
    <template #footer>
      <div class="flex justify-end gap-2">
        <Button
          label="Cancel"
          severity="secondary"
          outlined
          @click="onCancelDelete"
        />
        <Button label="Delete" @click="onConfirmDelete" />
      </div>
    </template>
  </Dialog>

  <Dialog
    v-model:visible="showRerunDialog"
    modal
    header="Rerun Session"
    :style="{ width: '25rem' }"
  >
    <div class="flex flex-col gap-4">
      <p class="text-surface-300">
        This will rerun the session with the same settings as it was originally
        run with.
      </p>
    </div>
    <template #footer>
      <div class="flex justify-end gap-2">
        <Button
          label="Cancel"
          severity="secondary"
          outlined
          @click="onCancelRerun"
        />
        <Button label="Rerun" @click="onConfirmRerun" />
      </div>
    </template>
  </Dialog>
</template>
