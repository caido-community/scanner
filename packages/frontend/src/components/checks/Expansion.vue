<script setup lang="ts">
import type { CheckMetadata } from "engine";

import { useTable } from "./useTable";

const { check } = defineProps<{
  check: CheckMetadata;
}>();

const { getAggressivityText } = useTable();
</script>

<template>
  <div class="px-6 py-4 space-y-2">
    <div>
      <span class="font-bold">Type:</span>
      <span class="capitalize ml-2">{{ check.type }}</span>
    </div>
    <div>
      <span class="font-bold">Aggressivity:</span>
      <span class="ml-2">{{ getAggressivityText(check) }}</span>
    </div>
    <div v-if="check.tags && check.tags.length > 0">
      <span class="font-bold">Tags:</span>
      <span class="ml-2">{{ check.tags.join(", ") }}</span>
    </div>
    <div v-if="check.description">
      <span class="font-bold">Description:</span>
      <span class="ml-2">{{ check.description }}</span>
    </div>
  </div>
</template>
