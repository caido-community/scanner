<script setup lang="ts">
import Button from "primevue/button";
import MenuBar from "primevue/menubar";
import { computed, onMounted, ref } from "vue";

import { useChecksService } from "@/services/checks";
import { useConfigService } from "@/services/config";
import { useQueueService } from "@/services/queue";
import { useScannerService } from "@/services/scanner";
import Checks from "@/views/Checks.vue";
import Dashboard from "@/views/Dashboard.vue";
import Queue from "@/views/Queue.vue";
import Settings from "@/views/Settings.vue";

const page = ref<"Dashboard" | "Queue" | "Checks" | "Settings">("Dashboard");
const items = [
  {
    label: "Dashboard",
    class: "mx-1",
    isActive: () => page.value === "Dashboard",
    command: () => {
      page.value = "Dashboard";
    },
  },
  {
    label: "Queue",
    class: "mx-1",
    isActive: () => page.value === "Queue",
    command: () => {
      page.value = "Queue";
    },
  },
  {
    label: "Checks",
    class: "mx-1",
    isActive: () => page.value === "Checks",
    command: () => {
      page.value = "Checks";
    },
  },
  {
    label: "Settings",
    class: "mx-1",
    isActive: () => page.value === "Settings",
    command: () => {
      page.value = "Settings";
    },
  },
];

const component = computed(() => {
  switch (page.value) {
    case "Dashboard":
      return Dashboard;
    case "Queue":
      return Queue;
    case "Checks":
      return Checks;
    case "Settings":
      return Settings;
    default:
      return undefined;
  }
});

const scannerService = useScannerService();
const checksService = useChecksService();
const configService = useConfigService();
const queueService = useQueueService();

onMounted(() => {
  scannerService.initialize();
  checksService.initialize();
  configService.initialize();
  queueService.initialize();
});
</script>

<template>
  <div class="h-full flex flex-col gap-1">
    <MenuBar :model="items" class="h-12 gap-2">
      <template #start>
        <div class="px-2 font-bold">Scanner</div>
      </template>

      <template #item="{ item }">
        <Button
          size="small"
          :severity="item.isActive() ? 'secondary' : 'contrast'"
          :outlined="item.isActive()"
          :text="!item.isActive()"
          :label="item.label"
          @mousedown="item.command"
        />
      </template>
    </MenuBar>
    <div class="flex-1 min-h-0">
      <component :is="component" />
    </div>
  </div>
</template>

<style scoped>
#plugin--scanner {
  height: 100%;
}
</style>
