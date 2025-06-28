<script setup lang="ts">
import { computed } from "vue";

import { ChecksTable } from "@/components/checks/ChecksTable";
import { useChecksService } from "@/services/checks";

const checksService = useChecksService();
const checksState = computed(() => checksService.getState());
</script>

<template>
  <ChecksTable :checks-state="checksState" />
</template>
