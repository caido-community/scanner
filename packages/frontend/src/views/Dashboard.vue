<script setup lang="ts">
import { computed } from "vue";

import { SessionsTable } from "@/components/dashboard";
import { useScannerService } from "@/services/scanner";

const scannerService = useScannerService();
const scannerState = computed(() => scannerService.getState());
</script>

<template>
  <SessionsTable :scanner-state="scannerState" />
</template>
