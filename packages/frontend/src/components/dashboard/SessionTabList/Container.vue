<script setup lang="ts">
import Card from "primevue/card";
import { computed } from "vue";

import Tab from "./Tab.vue";

import { useScannerService } from "@/services/scanner";
import { type SessionsState } from "@/types/scanner";

const { state } = defineProps<{
  state: SessionsState & { type: "Success" };
}>();

const scannerService = useScannerService();

const selectedSession = computed(() => {
  return scannerService.getSelectedSession();
});

const handleTabSelect = (sessionId: string) => {
  scannerService.selectSession(sessionId);
};

const handleRename = (sessionId: string, newName: string) => {
  scannerService.updateSessionTitle(sessionId, newName);
};

const handleDelete = (sessionId: string) => {
  scannerService.deleteScanSession(sessionId);
};

const handleDeleteOthers = (sessionId: string) => {
  scannerService.deleteOtherSessions(sessionId);
};
</script>

<template>
  <Card
    v-if="state.sessions.length > 0"
    class="h-fit"
    :pt="{
      body: { class: 'h-fit p-0' },
      content: { class: 'h-fit flex flex-col' },
    }"
  >
    <template #content>
      <div class="flex gap-2 p-4 overflow-x-auto">
        <Tab
          v-for="session in state.sessions"
          :key="session.id"
          :is-selected="selectedSession?.id === session.id"
          :label="session.title"
          :status="session.kind"
          @select="handleTabSelect(session.id)"
          @rename="(newName) => handleRename(session.id, newName)"
          @delete="handleDelete(session.id)"
          @delete-others="handleDeleteOthers(session.id)"
        />
      </div>
    </template>
  </Card>
</template>
