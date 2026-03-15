<script setup lang="ts">
import Card from "primevue/card";
import { computed } from "vue";

import { SessionPreview, SessionTabList } from "@/components/dashboard";
import { useScannerService } from "@/services/scanner";

const scannerService = useScannerService();
const scannerState = computed(() => scannerService.getState());
</script>

<template>
  <div class="flex flex-col h-full gap-1 overflow-y-auto">
    <Card
      class="h-fit"
      :pt="{
        body: { class: 'h-fit p-0' },
        content: { class: 'h-fit flex flex-col' },
      }"
    >
      <template #content>
        <div class="flex justify-between items-center p-4">
          <div>
            <h3 class="text-lg font-semibold">Sessions</h3>
            <p class="text-sm text-surface-300">
              Active and completed vulnerability scanning sessions.
            </p>
          </div>
        </div>
      </template>
    </Card>

    <SessionTabList
      v-if="scannerState.type === 'Success' && scannerState.sessions.length > 0"
      :state="scannerState"
    />

    <SessionPreview v-if="scannerState.type !== 'Error'" />
  </div>
</template>
