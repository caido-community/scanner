<script setup lang="ts">
import { computed } from "vue";

import { Settings } from "@/components/settings";
import { useConfigStore } from "@/stores/config";

const config = useConfigStore();

const state = computed(() => config.getState());
</script>

<template>
  <Settings :config-state="state" />
</template>
